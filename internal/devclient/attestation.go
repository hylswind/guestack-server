//go:build dev

package devclient

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"math/big"
	"time"
)

// ErrAttestation is returned for any verification failure.
var ErrAttestation = errors.New("attestation verification failed")

// Pins are what the login page pins in its constants block.
type Pins struct {
	RootSHA256 [32]byte
	PCRs       map[int][]byte
}

// VerifyAttestation verifies a document in the order of spec/channel.md and
// returns nil only if hpkePK is the key the document binds.
func VerifyAttestation(doc, hpkePK []byte, pins Pins, now time.Time) error {
	v, err := Decode(doc)
	if err != nil {
		return ErrAttestation
	}
	// Documents are untagged. Tag 18, which the AWS documentation describes,
	// is also accepted.
	if tag, ok := v.(Tag); ok {
		if tag.Number != 18 {
			return ErrAttestation
		}
		v = tag.Content
	}
	arr, ok := v.([]any)
	if !ok || len(arr) != 4 {
		return ErrAttestation
	}
	prot, ok1 := arr[0].([]byte)
	_, ok2 := arr[1].(map[any]any)
	payload, ok3 := arr[2].([]byte)
	sig, ok4 := arr[3].([]byte)
	if !ok1 || !ok2 || !ok3 || !ok4 || len(sig) != 96 {
		return ErrAttestation
	}
	ph, err := Decode(prot)
	if err != nil {
		return ErrAttestation
	}
	phm, ok := ph.(map[any]any)
	if !ok || len(phm) != 1 || phm[uint64(1)] != int64(-35) {
		return ErrAttestation
	}
	pv, err := Decode(payload)
	if err != nil {
		return ErrAttestation
	}
	pm, ok := pv.(map[any]any)
	if !ok {
		return ErrAttestation
	}
	leafDER, ok1 := pm["certificate"].([]byte)
	bundle, ok2 := pm["cabundle"].([]any)
	pcrs, ok3 := pm["nitrotpm_pcrs"].(map[any]any)
	userData, ok4 := pm["user_data"].([]byte)
	if !ok1 || !ok2 || !ok3 || !ok4 || len(bundle) == 0 || pm["digest"] != "SHA384" {
		return ErrAttestation
	}

	// 1. Certificate chain: root pin, then an explicit walk root → leaf.
	var chain []*x509.Certificate
	for _, b := range bundle {
		der, ok := b.([]byte)
		if !ok {
			return ErrAttestation
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return ErrAttestation
		}
		chain = append(chain, c)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return ErrAttestation
	}
	chain = append(chain, leaf)
	if sha256.Sum256(chain[0].Raw) != pins.RootSHA256 {
		return ErrAttestation
	}
	for i, c := range chain {
		if now.Before(c.NotBefore) || now.After(c.NotAfter) {
			return ErrAttestation
		}
		issuer := c
		if i > 0 {
			issuer = chain[i-1]
			if !issuer.IsCA {
				return ErrAttestation
			}
		}
		if c.CheckSignatureFrom(issuer) != nil {
			return ErrAttestation
		}
	}

	// 2. COSE signature with the leaf key (ES384, raw r‖s).
	leafKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || leafKey.Curve != elliptic.P384() {
		return ErrAttestation
	}
	digest := sha512.Sum384(sigStructure(prot, payload))
	r := new(big.Int).SetBytes(sig[:48])
	s := new(big.Int).SetBytes(sig[48:])
	if !ecdsa.Verify(leafKey, digest[:], r, s) {
		return ErrAttestation
	}

	// 3. Pinned PCRs.
	for i, want := range pins.PCRs {
		got, ok := pcrs[uint64(i)].([]byte)
		if !ok || subtle.ConstantTimeCompare(got, want) != 1 {
			return ErrAttestation
		}
	}

	// 4. Key binding.
	if !bytes.Equal(userData, hpkePK) {
		return ErrAttestation
	}
	return nil
}

// sigStructure encodes the COSE Sig_structure
// ["Signature1", protected, empty bstr, payload].
func sigStructure(prot, payload []byte) []byte {
	var b []byte
	b = append(b, 0x84)
	b = appendHead(b, 3, uint64(len("Signature1")))
	b = append(b, "Signature1"...)
	b = appendHead(b, 2, uint64(len(prot)))
	b = append(b, prot...)
	b = append(b, 0x40)
	b = appendHead(b, 2, uint64(len(payload)))
	return append(b, payload...)
}

func appendHead(b []byte, major byte, n uint64) []byte {
	switch {
	case n < 24:
		return append(b, major<<5|byte(n))
	case n <= 0xff:
		return append(b, major<<5|24, byte(n))
	case n <= 0xffff:
		return append(b, major<<5|25, byte(n>>8), byte(n))
	default:
		return append(b, major<<5|26, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
}
