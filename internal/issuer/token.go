// Package issuer assembles and signs identity tokens (spec/identity-token.md).
package issuer

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"strconv"

	"github.com/hylswind/guestack-server/internal/jose"
)

const (
	// Iss is the fixed issuer identifier. It is not a URL.
	Iss = "guestack"
	// TokenType is the identity token's "typ".
	TokenType = "guestack-id+jwt"
)

// ErrSign is returned for any signing failure. It carries no detail.
var ErrSign = errors.New("issuer: signing failed")

// Signer signs a SHA-256 digest with the issuer key (P-256) and returns an
// ASN.1 DER ECDSA signature, which is what AWS KMS returns.
type Signer interface {
	SignDigest(ctx context.Context, digest [32]byte) (der []byte, err error)
}

// Claims are the variable parts of an identity token's payload.
type Claims struct {
	Sub  string        // guest ID
	Exp  int64         // epoch_end
	Boot string        // b64u of 8 bytes chosen at process start
	Cnf  *jose.P256JWK // the user's key
}

// KeyID is the "kid" of an issuer key: the base64url RFC 7638 thumbprint.
func KeyID(k *jose.P256JWK) string {
	tp := k.Thumbprint()
	return jose.B64(tp[:])
}

// HeaderJSON is the identity token header, members in this fixed order.
func HeaderJSON(kid string) string {
	return `{"alg":"ES256","typ":"` + TokenType + `","kid":` + jose.MarshalString(kid) + `}`
}

// PayloadJSON is the identity token payload: exactly iss, sub, exp, boot,
// cnf, in that order.
func PayloadJSON(c Claims) string {
	jwk, _ := c.Cnf.MarshalJSON()
	return `{"iss":"` + Iss + `","sub":` + jose.MarshalString(c.Sub) +
		`,"exp":` + strconv.FormatInt(c.Exp, 10) +
		`,"boot":` + jose.MarshalString(c.Boot) +
		`,"cnf":{"jwk":` + string(jwk) + `}}`
}

// SigningInput is b64u(header) "." b64u(payload).
func SigningInput(kid string, c Claims) string {
	return jose.B64([]byte(HeaderJSON(kid))) + "." + jose.B64([]byte(PayloadJSON(c)))
}

// Issuer signs identity tokens with one key.
type Issuer struct {
	signer Signer
	pub    *jose.P256JWK
	kid    string
}

// New binds a signer to its public key. The kid is derived from the key.
func New(signer Signer, pub *ecdsa.PublicKey) (*Issuer, error) {
	k, err := jose.NewP256JWK(pub)
	if err != nil {
		return nil, err
	}
	return &Issuer{signer: signer, pub: k, kid: KeyID(k)}, nil
}

// KeyID returns the issuer key's kid.
func (i *Issuer) KeyID() string { return i.kid }

// Issue signs an identity token. The signature is converted from DER to raw
// r‖s and verified against the issuer public key before it is returned, so a
// signer that uses a different key fails here rather than at every RP.
func (i *Issuer) Issue(ctx context.Context, c Claims) (string, error) {
	if c.Cnf == nil {
		return "", ErrSign
	}
	input := SigningInput(i.kid, c)
	der, err := i.signer.SignDigest(ctx, sha256.Sum256([]byte(input)))
	if err != nil {
		return "", ErrSign
	}
	raw, err := jose.DERToRaw(der)
	if err != nil {
		return "", ErrSign
	}
	if jose.VerifyES256(i.pub.PublicKey(), input, raw) != nil {
		return "", ErrSign
	}
	return input + "." + jose.B64(raw), nil
}
