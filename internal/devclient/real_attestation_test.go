//go:build dev

package devclient

import (
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"testing"
	"time"

	"github.com/hylswind/guestack-server/internal/vectors"
)

// realVector is spec/vectors/attestation.json: a document recorded from a
// real instance. It is never regenerated.
type realVector struct {
	Description string            `json:"description"`
	Doc         string            `json:"doc"`
	HPKEPK      string            `json:"hpke_pk"`
	RootSHA256  string            `json:"nitro_root_sha256_hex"`
	PinnedPCRs  map[string]string `json:"pinned_pcrs_hex"`
	ValidAtMs   int64             `json:"valid_at_ms"`
	ExpiredAtMs int64             `json:"expired_at_ms"`
}

func loadRealVector(t *testing.T) (doc, pk []byte, pins Pins, v realVector) {
	t.Helper()
	vectors.Load(t, "attestation.json", &v)
	doc, err := base64.StdEncoding.DecodeString(v.Doc)
	if err != nil {
		t.Fatal(err)
	}
	pk, err = base64.RawURLEncoding.DecodeString(v.HPKEPK)
	if err != nil {
		t.Fatal(err)
	}
	root, err := hex.DecodeString(v.RootSHA256)
	if err != nil || len(root) != 32 {
		t.Fatal("bad root pin")
	}
	copy(pins.RootSHA256[:], root)
	pins.PCRs = map[int][]byte{}
	for k, h := range v.PinnedPCRs {
		i, err := strconv.Atoi(k)
		if err != nil {
			t.Fatal(err)
		}
		if pins.PCRs[i], err = hex.DecodeString(h); err != nil {
			t.Fatal(err)
		}
	}
	return doc, pk, pins, v
}

func TestRealAttestationVectors(t *testing.T) {
	doc, pk, pins, v := loadRealVector(t)

	// The vector keeps the encoding real instances use: an untagged
	// COSE_Sign1 whose payload is an indefinite-length map.
	top, err := Decode(doc)
	if err != nil {
		t.Fatal(err)
	}
	arr, ok := top.([]any)
	if !ok || len(arr) != 4 {
		t.Fatal("not an untagged COSE_Sign1")
	}
	if payload, ok := arr[2].([]byte); !ok || len(payload) == 0 || payload[0] != 0xbf {
		t.Fatal("payload is not an indefinite-length map")
	}

	valid := time.UnixMilli(v.ValidAtMs)
	if err := VerifyAttestation(doc, pk, pins, valid); err != nil {
		t.Fatalf("real document rejected: %v", err)
	}

	wrongRoot := pins
	wrongRoot.RootSHA256[0] ^= 1
	wrongPCR := Pins{RootSHA256: pins.RootSHA256, PCRs: map[int][]byte{}}
	for i, b := range pins.PCRs {
		wrongPCR.PCRs[i] = append([]byte(nil), b...)
	}
	wrongPCR.PCRs[4][0] ^= 1
	wrongKey := append([]byte(nil), pk...)
	wrongKey[len(wrongKey)-1] ^= 1

	cases := map[string]func() error{
		"expired leaf":   func() error { return VerifyAttestation(doc, pk, pins, time.UnixMilli(v.ExpiredAtMs)) },
		"wrong root pin": func() error { return VerifyAttestation(doc, pk, wrongRoot, valid) },
		"wrong PCR4":     func() error { return VerifyAttestation(doc, pk, wrongPCR, valid) },
		"other hpke_pk":  func() error { return VerifyAttestation(doc, wrongKey, pins, valid) },
		"signature flipped": func() error {
			d := append([]byte(nil), doc...)
			d[len(d)-1] ^= 1
			return VerifyAttestation(d, pk, pins, valid)
		},
	}
	for name, f := range cases {
		if f() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
