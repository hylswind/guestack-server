package telegram

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hylswind/guestack-server/internal/jose"
)

func rsaJWK(kid string, k *rsa.PublicKey, extra string) string {
	return `{"kid":"` + kid + `","kty":"RSA","alg":"RS256","n":"` + jose.B64(k.N.Bytes()) +
		`","e":"` + jose.B64(big.NewInt(int64(k.E)).Bytes()) + `"` + extra + `}`
}

func ecJWK(kid string, k *ecdsa.PublicKey, crv string) string {
	pt, _ := k.Bytes()
	return `{"kid":"` + kid + `","kty":"EC","alg":"ES256","use":"sig","crv":"` + crv + `","x":"` +
		jose.B64(pt[1:33]) + `","y":"` + jose.B64(pt[33:]) + `"}`
}

func TestParseJWKS(t *testing.T) {
	r, _ := rsa.GenerateKey(rand.Reader, 2048)
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	e, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	doc := `{"keys":[` + strings.Join([]string{
		rsaJWK("oidc-1", &r.PublicKey, ""),
		ecJWK("oidc-es256-1", &e.PublicKey, "P-256"),
		`{"kid":"oidc-eddsa-1","kty":"OKP","alg":"EdDSA","crv":"Ed25519","x":"AAAA"}`,
		`{"kid":"oidc-es256k-1","kty":"EC","alg":"ES256K","crv":"secp256k1","x":"AA","y":"AA"}`,
		rsaJWK("small", &small.PublicKey, ""),
		rsaJWK("enc", &r.PublicKey, `,"use":"enc"`),
		`{"kty":"RSA"}`,
	}, ",") + `]}`
	keys, err := ParseJWKS([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys["oidc-1"].Alg != "RS256" || keys["oidc-es256-1"].Alg != "ES256" {
		t.Errorf("got %v", keys)
	}
	for _, bad := range []string{`[]`, `{"keys":{}}`, `{}`, ``} {
		if _, err := ParseJWKS([]byte(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// tlsServer serves h over TLS and returns a Fetcher trusting only it.
func tlsServer(t *testing.T, h http.HandlerFunc) (*Fetcher, *time.Time) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	client := &http.Client{Timeout: fetchTimeout, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	f := newFetcher(srv.URL+"/.well-known/jwks.json", client)
	now := time.Unix(1_800_000_000, 0)
	f.now = func() time.Time { return now }
	return f, &now
}

func TestFetcherRefreshRateLimit(t *testing.T) {
	r, _ := rsa.GenerateKey(rand.Reader, 2048)
	var hits atomic.Int32
	var kid atomic.Value
	kid.Store("k1")
	f, now := tlsServer(t, func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Write([]byte(`{"keys":[` + rsaJWK(kid.Load().(string), &r.PublicKey, "") + `]}`))
	})
	ctx := context.Background()
	if _, err := f.Key(ctx, "k1"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Key(ctx, "k1"); err != nil || hits.Load() != 1 {
		t.Fatal("cached key refetched")
	}
	kid.Store("k2") // Telegram rotates
	if _, err := f.Key(ctx, "k2"); err != ErrUnknownKey || hits.Load() != 1 {
		t.Fatalf("refetched within the rate limit: %v, %d", err, hits.Load())
	}
	*now = now.Add(minFetchInterval)
	if _, err := f.Key(ctx, "k2"); err != nil || hits.Load() != 2 {
		t.Fatalf("no refresh after the interval: %v", err)
	}
	if _, err := f.Key(ctx, "nope"); err != ErrUnknownKey || hits.Load() != 2 {
		t.Fatal("unknown kid refetched within the rate limit")
	}
}

func TestFetcherRedirects(t *testing.T) {
	r, _ := rsa.GenerateKey(rand.Reader, 2048)
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"keys":[` + rsaJWK("k", &r.PublicKey, "") + `]}`))
	}))
	t.Cleanup(plain.Close)

	// https → https on the same host: followed.
	f, _ := tlsServer(t, func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/moved.json" {
			http.Redirect(w, req, "/moved.json", http.StatusMovedPermanently)
			return
		}
		w.Write([]byte(`{"keys":[` + rsaJWK("k", &r.PublicKey, "") + `]}`))
	})
	if _, err := f.Key(context.Background(), "k"); err != nil {
		t.Errorf("https → https redirect not followed: %v", err)
	}

	// https → http: refused, even though the http server would answer.
	f, _ = tlsServer(t, func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, plain.URL+"/.well-known/jwks.json", http.StatusFound)
	})
	if _, err := f.Key(context.Background(), "k"); err != ErrUnavailable {
		t.Errorf("https → http redirect followed: %v", err)
	}
}

func TestFetcherRefusesOversize(t *testing.T) {
	f, _ := tlsServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"keys":[],"pad":"` + strings.Repeat("a", maxJWKSBytes) + `"}`))
	})
	if _, err := f.Key(context.Background(), "k"); err != ErrUnavailable {
		t.Errorf("oversize: %v", err)
	}
}

func TestProductionFetcherURL(t *testing.T) {
	if NewFetcher().url != JWKSURL {
		t.Error("fetcher URL is not the constant")
	}
}

func TestAudArray(t *testing.T) {
	v := NewVerifier(StaticKeys{}, 7)
	for raw, want := range map[string]bool{`"7"`: true, `["7"]`: true, `["7","8"]`: false, `7`: false, `"8"`: false, `[]`: false} {
		if v.audOK([]byte(raw)) != want {
			t.Errorf("aud %s", raw)
		}
	}
}
