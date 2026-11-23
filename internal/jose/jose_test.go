package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestDecodeB64Strict(t *testing.T) {
	for _, s := range []string{"AA==", "AA=", "A+", "A/", "AB", "A", "AA\n"} {
		if _, err := DecodeB64(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
	if b, err := DecodeB64("AA"); err != nil || len(b) != 1 || b[0] != 0 {
		t.Error("AA rejected")
	}
	if b, err := DecodeB64(""); err != nil || len(b) != 0 {
		t.Error("empty rejected")
	}
}

func TestParseP256JWK(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k, err := NewP256JWK(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	good, _ := k.MarshalJSON()
	back, err := ParseP256JWK(good)
	if err != nil || !back.PublicKey().Equal(&priv.PublicKey) || back.Thumbprint() != k.Thumbprint() {
		t.Fatal("round trip failed")
	}
	x, y := k.x, k.y
	offCurveY := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE"
	d, _ := priv.Bytes()
	for name, s := range map[string]string{
		"private d":     `{"kty":"EC","crv":"P-256","x":"` + x + `","y":"` + y + `","d":"` + B64(d) + `"}`,
		"extra member":  `{"kty":"EC","crv":"P-256","x":"` + x + `","y":"` + y + `","use":"sig"}`,
		"missing y":     `{"kty":"EC","crv":"P-256","x":"` + x + `"}`,
		"wrong curve":   `{"kty":"EC","crv":"P-384","x":"` + x + `","y":"` + y + `"}`,
		"wrong kty":     `{"kty":"RSA","crv":"P-256","x":"` + x + `","y":"` + y + `"}`,
		"off curve":     `{"kty":"EC","crv":"P-256","x":"` + x + `","y":"` + offCurveY + `"}`,
		"short x":       `{"kty":"EC","crv":"P-256","x":"` + x[:42] + `","y":"` + y + `"}`,
		"number":        `{"kty":"EC","crv":"P-256","x":1,"y":"` + y + `"}`,
		"trailing data": string(good) + "{}",
		"array":         `[]`,
		"invalid utf8":  "{\"kty\":\"E\xffC\"}",
	} {
		if _, err := ParseP256JWK([]byte(s)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestES256(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sig, err := SignES256(priv, "a.b")
	if err != nil || len(sig) != 64 {
		t.Fatal(err)
	}
	if VerifyES256(&priv.PublicKey, "a.b", sig) != nil {
		t.Error("valid signature rejected")
	}
	if VerifyES256(&priv.PublicKey, "a.c", sig) == nil {
		t.Error("signature over other input accepted")
	}
	if VerifyES256(&priv.PublicKey, "a.b", sig[:63]) == nil {
		t.Error("short signature accepted")
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if VerifyES256(&p384.PublicKey, "a.b", sig) == nil {
		t.Error("P-384 key accepted")
	}
}

func TestParseCompact(t *testing.T) {
	for _, s := range []string{"", "a.b", "a.b.c.d", "a=.b.c", "e30.e30.A"} {
		if _, err := ParseCompact(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
	long := make([]byte, MaxCompactLen+1)
	for i := range long {
		long[i] = 'A'
	}
	if _, err := ParseCompact(string(long)); err == nil {
		t.Error("over-long input accepted")
	}
	c, err := ParseCompact("e30.e30.")
	if err != nil || string(c.Header) != "{}" || len(c.Signature) != 0 || c.SigningInput != "e30.e30" {
		t.Error("valid compact rejected")
	}
}
