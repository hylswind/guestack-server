// Package telegram verifies Telegram login id_tokens (spec/registration.md,
// rules 2–3) against Telegram's JWKS.
//
// The issuer, the JWKS URL and the client ID are compile-time constants
// and part of the measured image: nothing at run time can change them.
package telegram

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math/big"
	"strconv"
	"time"

	"github.com/hylswind/guestack-server/internal/jose"
)

const (
	// Issuer is the required "iss".
	Issuer = "https://oauth.telegram.org"
	// JWKSURL is the only URL the backend fetches keys from.
	JWKSURL = "https://oauth.telegram.org/.well-known/jwks.json"
)

// Fixed errors; none carries token data.
var (
	// ErrInvalid: the id_token fails verification (→ id_token_invalid).
	ErrInvalid = errors.New("telegram: id_token invalid")
	// ErrUnavailable: keys could not be obtained (→ internal).
	ErrUnavailable = errors.New("telegram: keys unavailable")
	// ErrUnknownKey: the kid is not in the JWKS (→ id_token_invalid).
	ErrUnknownKey = errors.New("telegram: unknown key")
)

// Key is one usable verification key from the JWKS.
type Key struct {
	Alg string // "RS256" or "ES256"
	Pub crypto.PublicKey
}

// KeySet returns the key for a kid.
type KeySet interface {
	Key(ctx context.Context, kid string) (Key, error)
}

// Claims are the id_token claims registration uses. The token is verified
// before Claims is returned.
type Claims struct {
	Iat         int64
	Nonce       string
	HasNonce    bool
	PhoneNumber string
	HasPhone    bool
}

// Verifier verifies id_tokens for one client ID.
type Verifier struct {
	keys     KeySet
	clientID string
	now      func() time.Time
}

// NewVerifier returns a verifier. clientID is the bot ID.
func NewVerifier(keys KeySet, clientID int64) *Verifier {
	return &Verifier{keys: keys, clientID: strconv.FormatInt(clientID, 10), now: time.Now}
}

// Verify checks signature, alg, iss, aud and exp, and extracts the claims.
// Returns ErrInvalid, ErrUnknownKey, or ErrUnavailable.
func (v *Verifier) Verify(ctx context.Context, token string) (*Claims, error) {
	c, err := jose.ParseCompact(token)
	if err != nil {
		return nil, ErrInvalid
	}
	var hdr struct {
		Alg  string          `json:"alg"`
		Kid  string          `json:"kid"`
		Crit json.RawMessage `json:"crit"`
	}
	if json.Unmarshal(c.Header, &hdr) != nil || hdr.Crit != nil || (hdr.Alg != "RS256" && hdr.Alg != "ES256") {
		return nil, ErrInvalid
	}
	alg, kid := hdr.Alg, hdr.Kid
	key, err := v.keys.Key(ctx, kid)
	if err != nil {
		return nil, err
	}
	if key.Alg != alg || !verifySig(key, c.SigningInput, c.Signature) {
		return nil, ErrInvalid
	}
	return v.claims(c.Payload)
}

func verifySig(k Key, input string, sig []byte) bool {
	switch k.Alg {
	case "RS256":
		pub, ok := k.Pub.(*rsa.PublicKey)
		if !ok {
			return false
		}
		d := sha256.Sum256([]byte(input))
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, d[:], sig) == nil
	case "ES256":
		pub, ok := k.Pub.(*ecdsa.PublicKey)
		return ok && jose.VerifyES256(pub, input, sig) == nil
	}
	return false
}

func (v *Verifier) claims(payload []byte) (*Claims, error) {
	var c struct {
		Iss   string          `json:"iss"`
		Aud   json.RawMessage `json:"aud"`
		Exp   *int64          `json:"exp"`
		Iat   *int64          `json:"iat"`
		Nonce *string         `json:"nonce"`
		Phone *string         `json:"phone_number"`
	}
	if json.Unmarshal(payload, &c) != nil || c.Iss != Issuer || !v.audOK(c.Aud) ||
		c.Exp == nil || c.Iat == nil || v.now().Unix() >= *c.Exp {
		return nil, ErrInvalid
	}
	out := &Claims{Iat: *c.Iat}
	if c.Nonce != nil {
		out.Nonce, out.HasNonce = *c.Nonce, true
	}
	if c.Phone != nil {
		out.PhoneNumber, out.HasPhone = *c.Phone, true
	}
	return out, nil
}

// audOK accepts the client ID as a string, or a one-element array of it.
func (v *Verifier) audOK(raw json.RawMessage) bool {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s == v.clientID
	}
	var arr []string
	return json.Unmarshal(raw, &arr) == nil && len(arr) == 1 && arr[0] == v.clientID
}

// ParseJWKS extracts the usable keys: RSA ≥ 2048 bits for RS256 and EC P-256
// for ES256. Other keys (EdDSA, secp256k1, encryption keys) and entries that
// do not parse are skipped. An error means the document itself is malformed.
func ParseJWKS(data []byte) (map[string]Key, error) {
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if json.Unmarshal(data, &doc) != nil || doc.Keys == nil {
		return nil, ErrUnavailable
	}
	out := make(map[string]Key)
	for _, e := range doc.Keys {
		if kid, k, ok := parseJWK(e); ok {
			out[kid] = k
		}
	}
	return out, nil
}

func parseJWK(raw json.RawMessage) (string, Key, bool) {
	var k struct {
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		Alg string `json:"alg"`
		Use string `json:"use"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
		N   string `json:"n"`
		E   string `json:"e"`
	}
	if json.Unmarshal(raw, &k) != nil || k.Kid == "" || (k.Use != "" && k.Use != "sig") {
		return "", Key{}, false
	}
	switch k.Kty {
	case "RSA":
		if k.Alg != "" && k.Alg != "RS256" {
			return "", Key{}, false
		}
		nb, err1 := jose.DecodeB64(k.N)
		eb, err2 := jose.DecodeB64(k.E)
		if err1 != nil || err2 != nil || len(eb) == 0 || len(eb) > 4 {
			return "", Key{}, false
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(new(big.Int).SetBytes(eb).Int64())}
		if pub.N.BitLen() < 2048 {
			return "", Key{}, false
		}
		return k.Kid, Key{Alg: "RS256", Pub: pub}, true
	case "EC":
		if (k.Alg != "" && k.Alg != "ES256") || k.Crv != "P-256" {
			return "", Key{}, false
		}
		xb, err1 := jose.DecodeB64(k.X)
		yb, err2 := jose.DecodeB64(k.Y)
		if err1 != nil || err2 != nil || len(xb) != 32 || len(yb) != 32 {
			return "", Key{}, false
		}
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, xb...), yb...))
		if err != nil {
			return "", Key{}, false
		}
		return k.Kid, Key{Alg: "ES256", Pub: pub}, true
	}
	return "", Key{}, false
}

// StaticKeys is a fixed key set (dev build and tests).
type StaticKeys map[string]Key

// Key implements KeySet.
func (s StaticKeys) Key(_ context.Context, kid string) (Key, error) {
	if k, ok := s[kid]; ok {
		return k, nil
	}
	return Key{}, ErrUnknownKey
}
