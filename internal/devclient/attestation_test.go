//go:build dev

package devclient

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/hylswind/guestack-server/internal/attest/devfake"
	"github.com/hylswind/guestack-server/internal/channel"
)

func devDoc(t *testing.T) ([]byte, []byte) {
	t.Helper()
	kp, err := channel.Generate()
	if err != nil {
		t.Fatal(err)
	}
	doc, err := devfake.New().Document(context.Background(), kp.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	return doc, kp.PublicKey()
}

func TestDevDocumentVerifies(t *testing.T) {
	doc, pk := devDoc(t)
	if err := VerifyAttestation(doc, pk, DevPins(), time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestAttestationTags(t *testing.T) {
	doc, pk := devDoc(t)
	if doc[0] != 0x84 {
		t.Fatal("dev document is not an untagged COSE_Sign1")
	}
	// 0xd2 is tag 18 (COSE_Sign1); 0xd3 is tag 19.
	if err := VerifyAttestation(append([]byte{0xd2}, doc...), pk, DevPins(), time.Now()); err != nil {
		t.Errorf("tag 18 rejected: %v", err)
	}
	if VerifyAttestation(append([]byte{0xd3}, doc...), pk, DevPins(), time.Now()) == nil {
		t.Error("tag 19 accepted")
	}
}

func TestAttestationNegative(t *testing.T) {
	doc, pk := devDoc(t)
	now := time.Now()
	wrongRoot := DevPins()
	wrongRoot.RootSHA256[0] ^= 1
	wrongPCR := DevPins()
	wrongPCR.PCRs[4] = bytes.Repeat([]byte{0}, 48)
	missingPCR := DevPins()
	missingPCR.PCRs[23+1] = bytes.Repeat([]byte{0}, 48) // PCR 24 is not in the document
	otherKP, _ := channel.Generate()

	cases := map[string]func() error{
		"wrong root pin": func() error { return VerifyAttestation(doc, pk, wrongRoot, now) },
		"wrong PCR":      func() error { return VerifyAttestation(doc, pk, wrongPCR, now) },
		"missing PCR":    func() error { return VerifyAttestation(doc, pk, missingPCR, now) },
		"key mismatch":   func() error { return VerifyAttestation(doc, otherKP.PublicKey(), DevPins(), now) },
		"expired leaf":   func() error { return VerifyAttestation(doc, pk, DevPins(), now.Add(devfake.LeafValidity+time.Minute)) },
		"not yet valid":  func() error { return VerifyAttestation(doc, pk, DevPins(), now.Add(-time.Hour)) },
		"signature flipped": func() error {
			d := append([]byte(nil), doc...)
			d[len(d)-1] ^= 1
			return VerifyAttestation(d, pk, DevPins(), now)
		},
		"user_data flipped": func() error {
			d := append([]byte(nil), doc...)
			i := bytes.Index(d, pk)
			d[i+10] ^= 1 // still a valid CBOR document; only the signature catches it
			return VerifyAttestation(d, d[i:i+len(pk)], DevPins(), now)
		},
	}
	for name, f := range cases {
		if f() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
