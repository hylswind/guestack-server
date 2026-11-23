// Package jose holds the small subset of JOSE that Guestack uses: strict
// base64url, compact JWS, P-256 public JWKs with their RFC 7638 thumbprint,
// ES256 over raw r‖s signatures, and DER→raw conversion for signatures that
// come from KMS.
//
// Errors are fixed values; none of them carries input data.
package jose

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"strings"
)

var (
	ErrMalformed = errors.New("jose: malformed")
	ErrSignature = errors.New("jose: bad signature")
	ErrKey       = errors.New("jose: invalid key")
)

// MaxCompactLen bounds every compact JWS this package parses.
const MaxCompactLen = 8192

var b64 = base64.RawURLEncoding.Strict()

// B64 encodes b as base64url without padding.
func B64(b []byte) string { return b64.EncodeToString(b) }

// DecodeB64 decodes base64url without padding. It rejects padding, characters
// outside the alphabet, and non-zero trailing bits, so every byte string has
// exactly one accepted encoding.
func DecodeB64(s string) ([]byte, error) {
	if strings.ContainsAny(s, "=\r\n") {
		return nil, ErrMalformed
	}
	b, err := b64.DecodeString(s)
	if err != nil {
		return nil, ErrMalformed
	}
	return b, nil
}

// Compact is a parsed compact JWS. Header and Payload are the decoded JSON
// bytes; nothing in them has been interpreted yet.
type Compact struct {
	Header       []byte
	Payload      []byte
	SigningInput string
	Signature    []byte
}

// ParseCompact splits and decodes a compact JWS without verifying it.
func ParseCompact(s string) (*Compact, error) {
	if len(s) > MaxCompactLen {
		return nil, ErrMalformed
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return nil, ErrMalformed
	}
	h, err := DecodeB64(parts[0])
	if err != nil {
		return nil, err
	}
	p, err := DecodeB64(parts[1])
	if err != nil {
		return nil, err
	}
	sig, err := DecodeB64(parts[2])
	if err != nil {
		return nil, err
	}
	return &Compact{Header: h, Payload: p, SigningInput: parts[0] + "." + parts[1], Signature: sig}, nil
}

// P256JWK is a validated P-256 public key.
type P256JWK struct {
	pub  *ecdsa.PublicKey
	x, y string // base64url coordinates, exactly as serialised
}

// DecodeJSON decodes exactly one JSON value into v, rejecting object members
// that v does not declare. It is used for the formats Guestack defines;
// Telegram's formats are decoded with plain json.Unmarshal.
func DecodeJSON(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return ErrMalformed
	}
	if _, err := dec.Token(); err != io.EOF {
		return ErrMalformed
	}
	return nil
}

// ParseP256JWK accepts only the members kty, crv, x, y (no private "d", no
// extras), requires kty "EC" and crv "P-256", 32-byte coordinates, and a point
// on the curve.
func ParseP256JWK(raw []byte) (*P256JWK, error) {
	var j struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}
	if DecodeJSON(raw, &j) != nil || j.Kty != "EC" || j.Crv != "P-256" {
		return nil, ErrKey
	}
	x, err := DecodeB64(j.X)
	if err != nil || len(x) != 32 {
		return nil, ErrKey
	}
	y, err := DecodeB64(j.Y)
	if err != nil || len(y) != 32 {
		return nil, ErrKey
	}
	point := append(append([]byte{4}, x...), y...)
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return nil, ErrKey
	}
	return &P256JWK{pub: pub, x: j.X, y: j.Y}, nil
}

// NewP256JWK wraps a P-256 public key.
func NewP256JWK(pub *ecdsa.PublicKey) (*P256JWK, error) {
	if pub == nil || pub.Curve != elliptic.P256() {
		return nil, ErrKey
	}
	point, err := pub.Bytes()
	if err != nil || len(point) != 65 {
		return nil, ErrKey
	}
	return &P256JWK{pub: pub, x: B64(point[1:33]), y: B64(point[33:])}, nil
}

// PublicKey returns the key.
func (k *P256JWK) PublicKey() *ecdsa.PublicKey { return k.pub }

// Canonical returns the RFC 7638 canonical JSON: required members only,
// lexicographic order, no whitespace. It is also the form Guestack uses
// whenever it serialises a JWK, apart from member order in cnf (see MarshalJSON).
func (k *P256JWK) Canonical() []byte {
	return []byte(`{"crv":"P-256","kty":"EC","x":"` + k.x + `","y":"` + k.y + `"}`)
}

// Thumbprint returns the RFC 7638 SHA-256 thumbprint (32 raw bytes).
func (k *P256JWK) Thumbprint() [32]byte { return sha256.Sum256(k.Canonical()) }

// MarshalJSON writes {"kty","crv","x","y"} in that order, the order used in
// the identity token's cnf claim.
func (k *P256JWK) MarshalJSON() ([]byte, error) {
	return []byte(`{"kty":"EC","crv":"P-256","x":"` + k.x + `","y":"` + k.y + `"}`), nil
}

// VerifyES256 verifies a raw 64-byte r‖s ES256 signature over signingInput.
func VerifyES256(pub *ecdsa.PublicKey, signingInput string, sig []byte) error {
	if pub == nil || pub.Curve != elliptic.P256() || len(sig) != 64 {
		return ErrSignature
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	digest := sha256.Sum256([]byte(signingInput))
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return ErrSignature
	}
	return nil
}

// SignES256 signs signingInput with a local key and returns the raw r‖s
// signature. Used for dev keys and tests; production identity tokens are
// signed by KMS and converted with DERToRaw.
func SignES256(priv *ecdsa.PrivateKey, signingInput string) ([]byte, error) {
	digest := sha256.Sum256([]byte(signingInput))
	der, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		return nil, err
	}
	return DERToRaw(der)
}

// DERToRaw converts an ASN.1 DER ECDSA-Sig-Value for a P-256 key into the
// 64-byte r‖s form JWS uses. It rejects trailing data, non-minimal encodings,
// zero or negative values, and values of more than 32 bytes.
func DERToRaw(der []byte) ([]byte, error) {
	var sig struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil || len(rest) != 0 {
		return nil, ErrMalformed
	}
	// encoding/asn1 accepts BER-style lengths in some cases; re-encoding and
	// comparing makes the accepted form exactly DER.
	if again, err := asn1.Marshal(sig); err != nil || string(again) != string(der) {
		return nil, ErrMalformed
	}
	out := make([]byte, 64)
	for i, v := range []*big.Int{sig.R, sig.S} {
		if v.Sign() <= 0 || v.BitLen() > 256 {
			return nil, ErrMalformed
		}
		v.FillBytes(out[i*32 : (i+1)*32])
	}
	return out, nil
}

// MarshalString JSON-encodes a string for hand-assembled JSON.
func MarshalString(s string) string {
	b, _ := json.Marshal(s) // cannot fail for a string
	return string(b)
}
