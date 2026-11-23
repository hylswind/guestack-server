// Package binding ties a Telegram id_token to the user's key
// (spec/registration.md): the nonce derived from the key's thumbprint, and
// the "pop" JWS that proves possession of the key.
package binding

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"

	"github.com/hylswind/guestack-server/internal/jose"
)

const (
	nonceLabel = "guestack/nonce/v1\x00"
	// PopType is the required "typ" of the pop JWS.
	PopType = "guestack-reg+jwt"
)

// ErrPop is the only error VerifyPop returns.
var ErrPop = errors.New("binding: pop invalid")

// Nonce = b64u(SHA-256("guestack/nonce/v1\0" ‖ thumbprint)), where thumbprint
// is the 32-byte RFC 7638 SHA-256 thumbprint of the user's JWK.
func Nonce(k *jose.P256JWK) string {
	tp := k.Thumbprint()
	h := sha256.New()
	h.Write([]byte(nonceLabel))
	h.Write(tp[:])
	return jose.B64(h.Sum(nil))
}

// NonceMatches compares the id_token's nonce claim with the nonce derived
// from k, in constant time.
func NonceMatches(k *jose.P256JWK, claim string) bool {
	return subtle.ConstantTimeCompare([]byte(Nonce(k)), []byte(claim)) == 1
}

// PopHash is the "h" member: b64u(SHA-256(id_token bytes)).
func PopHash(idToken string) string {
	h := sha256.Sum256([]byte(idToken))
	return jose.B64(h[:])
}

// VerifyPop checks a pop JWS: header {alg: ES256, typ: PopType} with no
// other members, payload {h} with no other members, h equal to
// PopHash(idToken), signature by k.
func VerifyPop(pop string, k *jose.P256JWK, idToken string) error {
	c, err := jose.ParseCompact(pop)
	if err != nil {
		return ErrPop
	}
	var hdr struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if jose.DecodeJSON(c.Header, &hdr) != nil || hdr.Alg != "ES256" || hdr.Typ != PopType {
		return ErrPop
	}
	if jose.VerifyES256(k.PublicKey(), c.SigningInput, c.Signature) != nil {
		return ErrPop
	}
	var p struct {
		H string `json:"h"`
	}
	if jose.DecodeJSON(c.Payload, &p) != nil || subtle.ConstantTimeCompare([]byte(p.H), []byte(PopHash(idToken))) != 1 {
		return ErrPop
	}
	return nil
}
