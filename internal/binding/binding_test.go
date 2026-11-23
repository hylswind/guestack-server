package binding

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/hylswind/guestack-server/internal/jose"
	"github.com/hylswind/guestack-server/internal/vectors"
)

type nonceVectors struct {
	Description string      `json:"description"`
	Label       string      `json:"label"`
	Cases       []nonceCase `json:"cases"`
}

type nonceCase struct {
	JWK           map[string]string `json:"jwk"`
	Canonical     string            `json:"thumbprint_input"`
	ThumbprintHex string            `json:"thumbprint_hex"`
	ThumbprintB64 string            `json:"thumbprint_b64u"`
	Nonce         string            `json:"nonce"`
}

type popVectors struct {
	Description string    `json:"description"`
	PrivateD    string    `json:"user_private_d_b64u"`
	JWK         jwkJSON   `json:"user_jwk"`
	IDToken     string    `json:"id_token"`
	H           string    `json:"h"`
	Valid       []string  `json:"valid"`
	Invalid     []popCase `json:"invalid"`
}

type jwkJSON map[string]string

type popCase struct {
	Reason string `json:"reason"`
	Pop    string `json:"pop"`
}

var keyLabels = []string{"guestack vector user key 1", "guestack vector user key 2", "guestack vector user key 3"}

func jwkMap(k *jose.P256JWK) map[string]string {
	pt, _ := k.PublicKey().Bytes()
	return map[string]string{"kty": "EC", "crv": "P-256", "x": jose.B64(pt[1:33]), "y": jose.B64(pt[33:])}
}

func mustJWK(t *testing.T, priv *ecdsa.PrivateKey) *jose.P256JWK {
	t.Helper()
	k, err := jose.NewP256JWK(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestNonceVectors(t *testing.T) {
	if vectors.Update() {
		v := nonceVectors{
			Description: "nonce = b64u(SHA-256(label ‖ thumbprint)), thumbprint = the 32 raw bytes of the RFC 7638 " +
				"SHA-256 thumbprint of the user's P-256 JWK (thumbprint_input is the canonical JSON that is hashed).",
			Label: nonceLabel,
		}
		for _, l := range keyLabels {
			k := mustJWK(t, vectors.FixedP256(t, l))
			tp := k.Thumbprint()
			v.Cases = append(v.Cases, nonceCase{
				JWK: jwkMap(k), Canonical: string(k.Canonical()),
				ThumbprintHex: hex.EncodeToString(tp[:]), ThumbprintB64: jose.B64(tp[:]), Nonce: Nonce(k),
			})
		}
		vectors.Write(t, "nonce.json", v)
	}

	var v nonceVectors
	vectors.Load(t, "nonce.json", &v)
	if v.Label != nonceLabel || len(v.Cases) == 0 {
		t.Fatal("bad vector file")
	}
	for _, c := range v.Cases {
		raw := []byte(`{"kty":"EC","crv":"P-256","x":"` + c.JWK["x"] + `","y":"` + c.JWK["y"] + `"}`)
		k, err := jose.ParseP256JWK(raw)
		if err != nil {
			t.Fatal(err)
		}
		if string(k.Canonical()) != c.Canonical {
			t.Errorf("canonical %s", k.Canonical())
		}
		tp := k.Thumbprint()
		if hex.EncodeToString(tp[:]) != c.ThumbprintHex || jose.B64(tp[:]) != c.ThumbprintB64 {
			t.Error("thumbprint mismatch")
		}
		if Nonce(k) != c.Nonce || !NonceMatches(k, c.Nonce) {
			t.Error("nonce mismatch")
		}
		// Independent recomputation from the vector's own fields.
		sum := sha256.Sum256([]byte(c.Canonical))
		n := sha256.Sum256(append([]byte(nonceLabel), sum[:]...))
		if jose.B64(n[:]) != c.Nonce {
			t.Error("independent nonce mismatch")
		}
	}
}

// signJWS assembles a compact JWS from literal header and payload JSON.
func signJWS(t *testing.T, priv *ecdsa.PrivateKey, header, payload string) string {
	t.Helper()
	input := jose.B64([]byte(header)) + "." + jose.B64([]byte(payload))
	sig, err := jose.SignES256(priv, input)
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + jose.B64(sig)
}

const vectorIDToken = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ2ZWN0b3IifQ.c2lnbmF0dXJl" // opaque to pop

func TestPopVectors(t *testing.T) {
	if vectors.Update() {
		priv := vectors.FixedP256(t, keyLabels[0])
		other := vectors.FixedP256(t, keyLabels[1])
		d, _ := priv.Bytes()
		h := PopHash(vectorIDToken)
		good := `{"alg":"ES256","typ":"guestack-reg+jwt"}`
		payload := `{"h":"` + h + `"}`
		input := jose.B64([]byte(good)) + "." + jose.B64([]byte(payload))
		v := popVectors{
			Description: "pop = compact JWS signed with the user key. Header exactly {alg: ES256, typ: guestack-reg+jwt}; " +
				"payload exactly {h}, h = b64u(SHA-256(id_token bytes)). Every invalid case yields pop_invalid. " +
				"ECDSA signatures are randomised: verify valid entries, do not compare bytes.",
			PrivateD: jose.B64(d), JWK: jwkMap(mustJWK(t, priv)), IDToken: vectorIDToken, H: h,
			Valid: []string{signJWS(t, priv, good, payload)},
			Invalid: []popCase{
				{"signed by another key", signJWS(t, other, good, payload)},
				{"h of another id_token", signJWS(t, priv, good, `{"h":"`+PopHash(vectorIDToken+"x")+`"}`)},
				{"typ of an RP proof", signJWS(t, priv, `{"alg":"ES256","typ":"guestack-proof+jwt"}`, `{"c":"AAAAAAAAAAAAAAAAAAAAAA","aud":"https://rp.example"}`)},
				{"typ of an RP proof with h payload", signJWS(t, priv, `{"alg":"ES256","typ":"guestack-proof+jwt"}`, payload)},
				{"typ missing", signJWS(t, priv, `{"alg":"ES256"}`, payload)},
				{"extra header member", signJWS(t, priv, `{"alg":"ES256","typ":"guestack-reg+jwt","kid":"x"}`, payload)},
				{"extra payload member", signJWS(t, priv, good, `{"h":"`+h+`","iat":1}`)},
				{"h padded", signJWS(t, priv, good, `{"h":"`+h+`="}`)},
				{"alg none", jose.B64([]byte(`{"alg":"none","typ":"guestack-reg+jwt"}`)) + "." + jose.B64([]byte(payload)) + "."},
				{"alg HS256", jose.B64([]byte(`{"alg":"HS256","typ":"guestack-reg+jwt"}`)) + "." + jose.B64([]byte(payload)) + "." + jose.B64(make([]byte, 32))},
				{"signature not raw r||s (DER)", input + "." + jose.B64(derSig(t, priv, input))},
				{"two parts", input},
			},
		}
		vectors.Write(t, "pop.json", v)
	}

	var v popVectors
	vectors.Load(t, "pop.json", &v)
	raw := []byte(`{"kty":"EC","crv":"P-256","x":"` + v.JWK["x"] + `","y":"` + v.JWK["y"] + `"}`)
	k, err := jose.ParseP256JWK(raw)
	if err != nil {
		t.Fatal(err)
	}
	if PopHash(v.IDToken) != v.H {
		t.Error("h mismatch")
	}
	if len(v.Valid) == 0 || len(v.Invalid) == 0 {
		t.Fatal("empty vectors")
	}
	for _, p := range v.Valid {
		if err := VerifyPop(p, k, v.IDToken); err != nil {
			t.Error("valid pop rejected")
		}
	}
	for _, c := range v.Invalid {
		if VerifyPop(c.Pop, k, v.IDToken) == nil {
			t.Errorf("%s: accepted", c.Reason)
		}
	}
}

func derSig(t *testing.T, priv *ecdsa.PrivateKey, input string) []byte {
	t.Helper()
	sum := sha256.Sum256([]byte(input))
	der, err := ecdsa.SignASN1(rand.Reader, priv, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestNonceMismatch(t *testing.T) {
	a := mustJWK(t, vectors.FixedP256(t, keyLabels[0]))
	b := mustJWK(t, vectors.FixedP256(t, keyLabels[1]))
	if NonceMatches(a, Nonce(b)) || NonceMatches(a, "") {
		t.Error("nonce for another key accepted")
	}
}
