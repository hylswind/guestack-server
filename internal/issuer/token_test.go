package issuer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/hylswind/guestack-server/internal/epoch"
	"github.com/hylswind/guestack-server/internal/jose"
	"github.com/hylswind/guestack-server/internal/vectors"
)

type tokenVectors struct {
	Description string            `json:"description"`
	IssuerD     string            `json:"issuer_private_d_b64u"`
	IssuerJWK   map[string]string `json:"issuer_jwk"`
	Kid         string            `json:"kid"`
	EpochID     string            `json:"epoch_id"`
	Claims      claimsJSON        `json:"claims"`
	HeaderJSON  string            `json:"header_json"`
	PayloadJSON string            `json:"payload_json"`
	Input       string            `json:"signing_input"`
	Token       string            `json:"identity"`
	DERToRaw    []derCase         `json:"der_to_raw"`
}

type claimsJSON struct {
	Sub  string            `json:"sub"`
	Exp  int64             `json:"exp"`
	Boot string            `json:"boot"`
	Cnf  map[string]string `json:"cnf_jwk"`
}

type derCase struct {
	Reason string `json:"reason"`
	DER    string `json:"der_hex"`
	Raw    string `json:"raw_hex,omitempty"` // empty: must be rejected
}

// localSigner signs with an in-memory key and returns DER, like KMS.
type localSigner struct{ priv *ecdsa.PrivateKey }

func (s localSigner) SignDigest(_ context.Context, d [32]byte) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, s.priv, d[:])
}

func jwkOf(t *testing.T, pub *ecdsa.PublicKey) *jose.P256JWK {
	t.Helper()
	k, err := jose.NewP256JWK(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func jwkMap(k *jose.P256JWK) map[string]string {
	pt, _ := k.PublicKey().Bytes()
	return map[string]string{"kty": "EC", "crv": "P-256", "x": jose.B64(pt[1:33]), "y": jose.B64(pt[33:])}
}

func parseJWKMap(t *testing.T, m map[string]string) *jose.P256JWK {
	t.Helper()
	k, err := jose.ParseP256JWK([]byte(`{"kty":"EC","crv":"P-256","x":"` + m["x"] + `","y":"` + m["y"] + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func derInts(r, s *big.Int) string {
	b, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func derCases() []derCase {
	one := big.NewInt(1)
	high := new(big.Int).Lsh(one, 255)              // 32 bytes, top bit set: DER needs a 0x00 prefix
	short := new(big.Int).SetBytes([]byte{0x7f, 1}) // 2 bytes: raw needs left padding
	max := new(big.Int).Sub(new(big.Int).Lsh(one, 256), one)
	tooBig := new(big.Int).Lsh(one, 256)
	raw := func(r, s *big.Int) string {
		out := make([]byte, 64)
		r.FillBytes(out[:32])
		s.FillBytes(out[32:])
		return hex.EncodeToString(out)
	}
	valid := derInts(high, short)
	return []derCase{
		{"r with high bit set (33-byte DER integer), short s", valid, raw(high, short)},
		{"short r, maximum s", derInts(short, max), raw(short, max)},
		{"r = s = 1", derInts(one, one), raw(one, one)},
		{"trailing byte after sequence", valid + "00", ""},
		{"r is zero", derInts(big.NewInt(0), one), ""},
		{"r is negative", derInts(big.NewInt(-1), one), ""},
		{"r longer than 32 bytes", derInts(tooBig, one), ""},
		{"non-minimal integer (extra 0x00)", "3008020300007f020101", ""},
		{"long-form length where short form is required", "30810602017f020101", ""},
		{"three integers", "3009020101020101020101", ""},
		{"empty", "", ""},
	}
}

func TestVectors(t *testing.T) {
	if vectors.Update() {
		priv := vectors.FixedP256(t, "guestack vector issuer key")
		user := vectors.FixedP256(t, "guestack vector user key 1")
		w, _ := epoch.Parse("2026-12")
		iss, err := New(localSigner{priv}, &priv.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		c := Claims{
			Sub: "3f2a9c1e-7b4d-8a6f-9e0c-5d2b1a7f3e48", Exp: w.End,
			Boot: jose.B64([]byte("bootval8")), Cnf: jwkOf(t, &user.PublicKey),
		}
		tok, err := iss.Issue(context.Background(), c)
		if err != nil {
			t.Fatal(err)
		}
		d, _ := priv.Bytes()
		v := tokenVectors{
			Description: "Identity token: compact JWS, ES256, raw r||s. header_json and payload_json are the exact " +
				"bytes that are base64url-encoded (member order fixed). kid = b64u RFC 7638 thumbprint of the issuer key. " +
				"exp = epoch_end of epoch_id. The signature is randomised: verify, do not compare. der_to_raw: " +
				"conversion of KMS DER signatures; entries without raw_hex must be rejected.",
			IssuerD: jose.B64(d), IssuerJWK: jwkMap(jwkOf(t, &priv.PublicKey)), Kid: iss.KeyID(), EpochID: "2026-12",
			Claims:     claimsJSON{Sub: c.Sub, Exp: c.Exp, Boot: c.Boot, Cnf: jwkMap(c.Cnf)},
			HeaderJSON: HeaderJSON(iss.KeyID()), PayloadJSON: PayloadJSON(c), Input: SigningInput(iss.KeyID(), c),
			Token: tok, DERToRaw: derCases(),
		}
		vectors.Write(t, "identity-token.json", v)
	}

	var v tokenVectors
	vectors.Load(t, "identity-token.json", &v)
	issuerKey := parseJWKMap(t, v.IssuerJWK)
	if KeyID(issuerKey) != v.Kid {
		t.Error("kid mismatch")
	}
	w, err := epoch.Parse(v.EpochID)
	if err != nil || w.End != v.Claims.Exp {
		t.Error("exp is not epoch_end")
	}
	c := Claims{Sub: v.Claims.Sub, Exp: v.Claims.Exp, Boot: v.Claims.Boot, Cnf: parseJWKMap(t, v.Claims.Cnf)}
	if HeaderJSON(v.Kid) != v.HeaderJSON || PayloadJSON(c) != v.PayloadJSON || SigningInput(v.Kid, c) != v.Input {
		t.Error("serialisation mismatch")
	}
	parts := strings.Split(v.Token, ".")
	if len(parts) != 3 || parts[0]+"."+parts[1] != v.Input {
		t.Fatal("token does not carry the signing input")
	}
	sig, err := jose.DecodeB64(parts[2])
	if err != nil || jose.VerifyES256(issuerKey.PublicKey(), v.Input, sig) != nil {
		t.Error("token signature does not verify")
	}
	// The vector's private key must match its public key.
	d, _ := jose.DecodeB64(v.IssuerD)
	priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
	if err != nil || !priv.PublicKey.Equal(issuerKey.PublicKey()) {
		t.Error("issuer private key does not match issuer_jwk")
	}

	if len(v.DERToRaw) == 0 {
		t.Fatal("no der cases")
	}
	for _, c := range v.DERToRaw {
		der, _ := hex.DecodeString(c.DER)
		raw, err := jose.DERToRaw(der)
		switch {
		case c.Raw == "" && err == nil:
			t.Errorf("%s: accepted", c.Reason)
		case c.Raw != "" && (err != nil || hex.EncodeToString(raw) != c.Raw):
			t.Errorf("%s: got %x %v", c.Reason, raw, err)
		}
	}
}

type wrongKeySigner struct{ priv *ecdsa.PrivateKey }

func (s wrongKeySigner) SignDigest(_ context.Context, d [32]byte) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, s.priv, d[:])
}

type failingSigner struct{}

func (failingSigner) SignDigest(context.Context, [32]byte) ([]byte, error) {
	return nil, errors.New("kms down")
}

func TestIssueRejectsBadSigners(t *testing.T) {
	priv := vectors.FixedP256(t, "guestack vector issuer key")
	user := vectors.FixedP256(t, "guestack vector user key 1")
	c := Claims{Sub: "3f2a9c1e-7b4d-8a6f-9e0c-5d2b1a7f3e48", Exp: 1, Boot: "AAAAAAAAAAA", Cnf: jwkOf(t, &user.PublicKey)}
	other := vectors.FixedP256(t, "some other key")
	for name, s := range map[string]Signer{"wrong key": wrongKeySigner{other}, "failing": failingSigner{}} {
		iss, err := New(s, &priv.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := iss.Issue(context.Background(), c); err != ErrSign {
			t.Errorf("%s: %v", name, err)
		}
	}
}
