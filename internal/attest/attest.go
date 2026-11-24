// Package attest provides the attestation document that binds the channel
// key (spec/channel.md) and keeps a fresh copy for GET /attestation.
package attest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync/atomic"
	"time"

	"github.com/hylswind/guestack-server/internal/jose"
	"github.com/hylswind/guestack-server/internal/safelog"
)

// Provider returns a CBOR COSE_Sign1 attestation document whose user_data
// is exactly userData.
type Provider interface {
	Document(ctx context.Context, userData []byte) ([]byte, error)
}

// ErrUnavailable is returned when no document can be produced.
var ErrUnavailable = errors.New("attest: document unavailable")

// RefreshInterval is how often the document is renewed. It must stay well
// below the leaf certificate's validity, which is 3 hours on a real instance
// (spec/external-notes.md) and in the dev build.
const RefreshInterval = 10 * time.Minute

// Cache holds the current GET /attestation response body.
type Cache struct {
	p      Provider
	hpkePK []byte
	body   atomic.Pointer[[]byte]
}

// NewCache fetches the first document. Startup fails if that fails.
func NewCache(ctx context.Context, p Provider, hpkePK []byte) (*Cache, error) {
	c := &Cache{p: p, hpkePK: append([]byte(nil), hpkePK...)}
	if err := c.refresh(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

// Body returns the JSON body {"doc": base64, "hpke_pk": b64u}.
func (c *Cache) Body() []byte { return *c.body.Load() }

func (c *Cache) refresh(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	doc, err := c.p.Document(ctx, c.hpkePK)
	if err != nil || len(doc) == 0 {
		return ErrUnavailable
	}
	body, err := json.Marshal(struct {
		Doc    string `json:"doc"`
		HPKEPK string `json:"hpke_pk"`
	}{base64.StdEncoding.EncodeToString(doc), jose.B64(c.hpkePK)})
	if err != nil {
		return ErrUnavailable
	}
	c.body.Store(&body)
	return nil
}

// Run refreshes the document every RefreshInterval until ctx ends. On a
// failed refresh the previous document stays in place.
func (c *Cache) Run(ctx context.Context) {
	t := time.NewTicker(RefreshInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			safelog.Go(func() {
				if c.refresh(ctx) != nil {
					safelog.AttestRefreshErr.Inc()
					safelog.Log(safelog.AttestationRefreshFailed)
					return
				}
				safelog.AttestRefreshOK.Inc()
			})
		}
	}
}
