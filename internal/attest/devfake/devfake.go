//go:build dev

// Package devfake emits attestation documents in the real NitroTPM format
// (spec/channel.md), signed under the throwaway dev root of
// internal/devkeys, with fixed dev PCRs. The login page verifies them with its
// normal code path, given the dev root hash and dev PCRs in a test copy of
// its constants block.
package devfake

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"

	"github.com/hylswind/guestack-server/internal/attest"
	"github.com/hylswind/guestack-server/internal/devkeys"
)

// LeafValidity is the dev leaf certificate lifetime.
const LeafValidity = 3 * time.Hour

// Provider is the dev attestation provider.
type Provider struct {
	root, inter *x509.Certificate
	interKey    *ecdsa.PrivateKey
	pcrs        map[int][]byte
	now         func() time.Time
}

// New returns a dev provider.
func New() *Provider {
	root, _ := devkeys.NitroRoot()
	inter, interKey := devkeys.NitroIntermediate()
	return &Provider{root: root, inter: inter, interKey: interKey, pcrs: devkeys.PCRs(), now: time.Now}
}

// Document implements attest.Provider.
func (p *Provider) Document(_ context.Context, userData []byte) ([]byte, error) {
	now := p.now()
	leafKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, attest.ErrUnavailable
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 63))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "guestack-dev-attestation-leaf", Organization: []string{"Guestack dev"}},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(LeafValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, tmpl, p.inter, &leafKey.PublicKey, p.interKey)
	if err != nil {
		return nil, attest.ErrUnavailable
	}

	var pl cbor
	pl.mapHead(9)
	pl.text("module_id")
	pl.text(devkeys.Marker)
	pl.text("digest")
	pl.text("SHA384")
	pl.text("timestamp")
	pl.uint(uint64(now.UnixMilli()))
	pl.text("nitrotpm_pcrs")
	pl.mapHead(len(p.pcrs))
	for i := range len(p.pcrs) {
		pl.uint(uint64(i))
		pl.bytes(p.pcrs[i])
	}
	pl.text("certificate")
	pl.bytes(leafDER)
	pl.text("cabundle")
	pl.array(2)
	pl.bytes(p.root.Raw) // root first
	pl.bytes(p.inter.Raw)
	pl.text("public_key")
	pl.null()
	pl.text("user_data")
	pl.bytes(userData)
	pl.text("nonce")
	pl.null()

	var prot cbor
	prot.mapHead(1)
	prot.uint(1)
	prot.int(-35) // ES384

	// Sig_structure = ["Signature1", protected, external_aad, payload]
	var sigStruct cbor
	sigStruct.array(4)
	sigStruct.text("Signature1")
	sigStruct.bytes(prot.b)
	sigStruct.bytes(nil)
	sigStruct.bytes(pl.b)
	digest := sha512.Sum384(sigStruct.b)
	r, s, err := ecdsa.Sign(rand.Reader, leafKey, digest[:])
	if err != nil {
		return nil, attest.ErrUnavailable
	}
	sig := make([]byte, 96)
	r.FillBytes(sig[:48])
	s.FillBytes(sig[48:])

	var doc cbor
	doc.tag(18)
	doc.array(4)
	doc.bytes(prot.b)
	doc.mapHead(0)
	doc.bytes(pl.b)
	doc.bytes(sig)
	return doc.b, nil
}
