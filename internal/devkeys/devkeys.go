//go:build dev

// Package devkeys holds the throwaway key material of the dev build. Every
// key here is public and worthless. It exists so that the frontend and RP SDK
// can test against a local backend without dev-only code paths in the login page:
// the dev backend emits real-format attestation documents under the dev
// root, accepts id_tokens signed by the dev Telegram keys, and signs identity
// tokens with the dev issuer key.
//
// The whole package is build-tagged "dev"; the production binary contains
// none of it (checked by cmd/guestackd's no-dev-symbols test).
package devkeys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"strconv"
)

// Marker is a string present only in dev builds.
const Marker = "GUESTACK-DEV-BUILD-NOT-FOR-PRODUCTION"

var (
	//go:embed nitro-root.key.pem
	rootKeyPEM []byte
	//go:embed nitro-root.crt.pem
	rootCertPEM []byte
	//go:embed nitro-intermediate.key.pem
	interKeyPEM []byte
	//go:embed nitro-intermediate.crt.pem
	interCertPEM []byte
	//go:embed telegram-rs256.key.pem
	tgRSAPEM []byte
	//go:embed telegram-es256.key.pem
	tgECPEM []byte
	//go:embed issuer.key.pem
	issuerPEM []byte
)

// Dev Telegram constants.
const (
	TelegramClientID int64 = 1000000001
	TelegramRS256Kid       = "dev-rs256-1"
	TelegramES256Kid       = "dev-es256-1"
)

func block(b []byte) []byte {
	p, _ := pem.Decode(b)
	if p == nil {
		panic("devkeys: bad PEM")
	}
	return p.Bytes
}

func key(b []byte) crypto.Signer {
	k, err := x509.ParsePKCS8PrivateKey(block(b))
	if err != nil {
		panic("devkeys: bad key")
	}
	return k.(crypto.Signer)
}

func cert(b []byte) *x509.Certificate {
	c, err := x509.ParseCertificate(block(b))
	if err != nil {
		panic("devkeys: bad certificate")
	}
	return c
}

// NitroRoot returns the dev attestation root certificate and key (P-384).
func NitroRoot() (*x509.Certificate, *ecdsa.PrivateKey) {
	return cert(rootCertPEM), key(rootKeyPEM).(*ecdsa.PrivateKey)
}

// NitroIntermediate returns the dev intermediate certificate and key (P-384).
func NitroIntermediate() (*x509.Certificate, *ecdsa.PrivateKey) {
	return cert(interCertPEM), key(interKeyPEM).(*ecdsa.PrivateKey)
}

// TelegramRS256 is the dev Telegram RSA key (kid TelegramRS256Kid).
func TelegramRS256() *rsa.PrivateKey { return key(tgRSAPEM).(*rsa.PrivateKey) }

// TelegramES256 is the dev Telegram P-256 key (kid TelegramES256Kid).
func TelegramES256() *ecdsa.PrivateKey { return key(tgECPEM).(*ecdsa.PrivateKey) }

// Issuer is the dev identity-token issuer key (P-256).
func Issuer() *ecdsa.PrivateKey { return key(issuerPEM).(*ecdsa.PrivateKey) }

// PCRs are the fixed dev PCR values: PCR i = SHA-384("guestack dev pcr " ‖ i)
// for i in 0..23.
func PCRs() map[int][]byte {
	out := make(map[int][]byte, 24)
	for i := range 24 {
		h := sha512.Sum384([]byte("guestack dev pcr " + strconv.Itoa(i)))
		out[i] = h[:]
	}
	return out
}
