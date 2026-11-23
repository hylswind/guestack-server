package telegram

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/hylswind/guestack-server/internal/safelog"
)

const (
	maxJWKSBytes     = 64 << 10
	minFetchInterval = 60 * time.Second
	fetchTimeout     = 10 * time.Second
)

// Fetcher is the production KeySet: Telegram's JWKS fetched over HTTPS from
// JWKSURL only, cached in memory, refreshed on an unknown kid at most once
// per minute.
type Fetcher struct {
	url    string
	client *http.Client
	now    func() time.Time

	mu        sync.Mutex
	keys      map[string]Key
	lastFetch time.Time
}

// NewFetcher returns a Fetcher for JWKSURL.
func NewFetcher() *Fetcher {
	return newFetcher(JWKSURL, &http.Client{Timeout: fetchTimeout})
}

// newFetcher installs the redirect policy on client.
func newFetcher(url string, client *http.Client) *Fetcher {
	client.CheckRedirect = httpsOnlyRedirects
	return &Fetcher{url: url, client: client, now: time.Now}
}

var errRedirect = errors.New("telegram: redirect refused")

// httpsOnlyRedirects follows redirects Telegram issues (so registration keeps
// working if the file moves), but only to https: targets. The operator
// controls the network and the JWKS decides which id_token signatures are
// accepted, so it must never be fetched without TLS (spec/registration.md).
// TLS certificates are validated on every hop by the transport.
func httpsOnlyRedirects(req *http.Request, via []*http.Request) error {
	if req.URL.Scheme != "https" || len(via) >= 10 {
		return errRedirect
	}
	return nil
}

// Key implements KeySet.
func (f *Fetcher) Key(ctx context.Context, kid string) (Key, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if k, ok := f.keys[kid]; ok {
		return k, nil
	}
	if !f.lastFetch.IsZero() && f.now().Sub(f.lastFetch) < minFetchInterval {
		if f.keys == nil {
			return Key{}, ErrUnavailable
		}
		return Key{}, ErrUnknownKey
	}
	f.lastFetch = f.now()
	keys, err := f.fetch(ctx)
	if err != nil {
		safelog.JWKSFetchFailed.Inc()
		if f.keys == nil {
			return Key{}, ErrUnavailable
		}
		return Key{}, ErrUnknownKey
	}
	safelog.JWKSFetchOK.Inc()
	f.keys = keys
	if k, ok := f.keys[kid]; ok {
		return k, nil
	}
	return Key{}, ErrUnknownKey
}

var errFetch = errors.New("telegram: jwks fetch failed")

func (f *Fetcher) fetch(ctx context.Context) (map[string]Key, error) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.url, nil)
	if err != nil {
		return nil, errFetch
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, errFetch
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errFetch
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil || len(body) > maxJWKSBytes {
		return nil, errFetch
	}
	keys, err := ParseJWKS(body)
	if err != nil || len(keys) == 0 {
		return nil, errFetch
	}
	return keys, nil
}
