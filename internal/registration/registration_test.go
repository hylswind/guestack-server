package registration

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/hylswind/guestack-server/internal/binding"
	"github.com/hylswind/guestack-server/internal/epoch"
	"github.com/hylswind/guestack-server/internal/issuer"
	"github.com/hylswind/guestack-server/internal/jose"
	"github.com/hylswind/guestack-server/internal/secret"
	"github.com/hylswind/guestack-server/internal/telegram"
)

const clientID = 4242

var (
	tgRSA, _  = rsa.GenerateKey(rand.Reader, 2048)
	tgEC, _   = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
)

type derSigner struct{ k *ecdsa.PrivateKey }

func (s derSigner) SignDigest(_ context.Context, d [32]byte) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, s.k, d[:])
}

type fixture struct {
	svc    *Service
	window epoch.Window
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	w, err := epoch.Parse(time.Now().UTC().Format("2006-01"))
	if err != nil {
		t.Fatal(err)
	}
	keys := telegram.StaticKeys{
		"rsa": {Alg: "RS256", Pub: &tgRSA.PublicKey},
		"ec":  {Alg: "ES256", Pub: &tgEC.PublicKey},
	}
	iss, err := issuer.New(derSigner{issKey}, &issKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{svc: New(telegram.NewVerifier(keys, clientID), secret.New(), iss, w, "AAAAAAAAAAA"), window: w}
}

// tok is a Telegram id_token under construction.
type tok struct {
	header string // literal JSON; default {"alg":"RS256","kid":"rsa"}
	claims map[string]any
	key    string // "rsa", "ec", or "none" (empty signature)
}

func baseClaims(user *ecdsa.PrivateKey) map[string]any {
	jwk, _ := jose.NewP256JWK(&user.PublicKey)
	now := time.Now().Unix()
	return map[string]any{
		"iss": telegram.Issuer, "aud": "4242", "sub": "1", "iat": now, "exp": now + 30,
		"nonce": binding.Nonce(jwk), "phone_number": "15550001234",
	}
}

func (t tok) mint() string {
	if t.header == "" {
		t.header = `{"alg":"RS256","kid":"rsa"}`
	}
	payload, _ := json.Marshal(t.claims)
	input := jose.B64([]byte(t.header)) + "." + jose.B64(payload)
	var sig []byte
	switch t.key {
	case "ec":
		sig, _ = jose.SignES256(tgEC, input)
	case "none":
	default:
		d := sha256.Sum256([]byte(input))
		sig, _ = rsa.SignPKCS1v15(rand.Reader, tgRSA, crypto.SHA256, d[:])
	}
	return input + "." + jose.B64(sig)
}

func params(user *ecdsa.PrivateKey, idToken, pop string) json.RawMessage {
	jwk, _ := jose.NewP256JWK(&user.PublicKey)
	j, _ := jwk.MarshalJSON()
	if pop == "" {
		pop = popFor(user, idToken)
	}
	return json.RawMessage(`{"id_token":` + jose.MarshalString(idToken) + `,"jwk":` + string(j) + `,"pop":` + jose.MarshalString(pop) + `}`)
}

func popFor(user *ecdsa.PrivateKey, idToken string) string {
	return signJWS(user, `{"alg":"ES256","typ":"guestack-reg+jwt"}`, `{"h":"`+binding.PopHash(idToken)+`"}`)
}

func signJWS(k *ecdsa.PrivateKey, header, payload string) string {
	input := jose.B64([]byte(header)) + "." + jose.B64([]byte(payload))
	sig, _ := jose.SignES256(k, input)
	return input + "." + jose.B64(sig)
}

func newUser() *ecdsa.PrivateKey {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return k
}

func TestSuccess(t *testing.T) {
	f := newFixture(t)
	u := newUser()
	for _, key := range []string{"rsa", "ec"} {
		h := `{"alg":"RS256","kid":"rsa"}`
		if key == "ec" {
			h = `{"alg":"ES256","kid":"ec","typ":"JWT"}`
		}
		id, code := f.svc.Register(context.Background(), params(u, tok{header: h, claims: baseClaims(u), key: key}.mint(), ""))
		if code != OK || strings.Count(id, ".") != 2 {
			t.Fatalf("%s: %q %q", key, id, code)
		}
	}
}

func TestRules(t *testing.T) {
	f := newFixture(t)
	u, other := newUser(), newUser()
	mod := func(fn func(map[string]any)) map[string]any {
		c := baseClaims(u)
		fn(c)
		return c
	}
	good := tok{claims: baseClaims(u)}.mint()
	cases := []struct {
		name   string
		params json.RawMessage
		want   Code
	}{
		{"params not an object", json.RawMessage(`[]`), BadRequest},
		{"missing pop", json.RawMessage(`{"id_token":"a","jwk":{}}`), BadRequest},
		{"extra member", json.RawMessage(`{"id_token":"a","jwk":{},"pop":"b","x":1}`), BadRequest},
		{"jwk not an object", json.RawMessage(`{"id_token":"a","jwk":"k","pop":"b"}`), BadRequest},
		{"id_token not a string", json.RawMessage(`{"id_token":1,"jwk":{},"pop":"b"}`), BadRequest},

		{"garbage id_token", params(u, "a.b.c", ""), IDTokenInvalid},
		{"alg none", params(u, tok{header: `{"alg":"none","kid":"rsa"}`, claims: baseClaims(u), key: "none"}.mint(), ""), IDTokenInvalid},
		{"alg HS256", params(u, tok{header: `{"alg":"HS256","kid":"rsa"}`, claims: baseClaims(u)}.mint(), ""), IDTokenInvalid},
		{"alg EdDSA", params(u, tok{header: `{"alg":"EdDSA","kid":"rsa"}`, claims: baseClaims(u)}.mint(), ""), IDTokenInvalid},
		{"RS256 header, EC key", params(u, tok{header: `{"alg":"RS256","kid":"ec"}`, claims: baseClaims(u), key: "ec"}.mint(), ""), IDTokenInvalid},
		{"unknown kid", params(u, tok{header: `{"alg":"RS256","kid":"zzz"}`, claims: baseClaims(u)}.mint(), ""), IDTokenInvalid},
		{"crit header", params(u, tok{header: `{"alg":"RS256","kid":"rsa","crit":["x"]}`, claims: baseClaims(u)}.mint(), ""), IDTokenInvalid},
		{"tampered signature", params(u, good[:len(good)-4]+"AAAA", ""), IDTokenInvalid},
		{"wrong aud", params(u, tok{claims: mod(func(c map[string]any) { c["aud"] = "4243" })}.mint(), ""), IDTokenInvalid},
		{"numeric aud", params(u, tok{claims: mod(func(c map[string]any) { c["aud"] = 4242 })}.mint(), ""), IDTokenInvalid},
		{"wrong iss", params(u, tok{claims: mod(func(c map[string]any) { c["iss"] = "https://oauth.telegram.org/" })}.mint(), ""), IDTokenInvalid},
		{"expired", params(u, tok{claims: mod(func(c map[string]any) { c["exp"] = time.Now().Unix() - 1 })}.mint(), ""), IDTokenInvalid},
		{"exp not an integer", params(u, tok{claims: mod(func(c map[string]any) { c["exp"] = "9999999999" })}.mint(), ""), IDTokenInvalid},
		{"no iat", params(u, tok{claims: mod(func(c map[string]any) { delete(c, "iat") })}.mint(), ""), IDTokenInvalid},
		{"phone_number not a string", params(u, tok{claims: mod(func(c map[string]any) { c["phone_number"] = 15550001234 })}.mint(), ""), IDTokenInvalid},

		{"private jwk", json.RawMessage(strings.Replace(string(params(u, good, "")), `"kty":"EC"`, `"kty":"EC","d":"AA"`, 1)), BadRequest},

		{"nonce for another key", params(u, tok{claims: mod(func(c map[string]any) {
			j, _ := jose.NewP256JWK(&other.PublicKey)
			c["nonce"] = binding.Nonce(j)
		})}.mint(), ""), KeyBindingFailed},
		{"no nonce", params(u, tok{claims: mod(func(c map[string]any) { delete(c, "nonce") })}.mint(), ""), KeyBindingFailed},
		{"another key presents the token", params(other, good, ""), KeyBindingFailed},

		{"pop by another key", params(u, good, popFor(other, good)), PopInvalid},
		{"pop over another token", params(u, good, popFor(u, "x")), PopInvalid},
		{"RP-style proof as pop", params(u, good, signJWS(u, `{"alg":"ES256","typ":"guestack-proof+jwt"}`, `{"c":"AAAAAAAAAAAAAAAAAAAAAA","aud":"https://rp.example"}`)), PopInvalid},
		{"pop with wrong typ but right h", params(u, good, signJWS(u, `{"alg":"ES256","typ":"guestack-proof+jwt"}`, `{"h":"`+binding.PopHash(good)+`"}`)), PopInvalid},

		{"iat = epoch_start - 1", params(u, tok{claims: mod(func(c map[string]any) { c["iat"] = f.window.Start - 1 })}.mint(), ""), EpochNotActive},
		{"iat = epoch_end", params(u, tok{claims: mod(func(c map[string]any) { c["iat"] = f.window.End })}.mint(), ""), EpochNotActive},

		{"no phone", params(u, tok{claims: mod(func(c map[string]any) { delete(c, "phone_number") })}.mint(), ""), PhoneNotShared},
		{"malformed phone", params(u, tok{claims: mod(func(c map[string]any) { c["phone_number"] = "1555 000" })}.mint(), ""), IDTokenInvalid},
		{"anonymous number", params(u, tok{claims: mod(func(c map[string]any) { c["phone_number"] = "+888012345678" })}.mint(), ""), PhoneNotAllowed},
	}
	for _, c := range cases {
		id, code := f.svc.Register(context.Background(), c.params)
		if code != c.want || id != "" {
			t.Errorf("%s: got %q (identity %d bytes), want %q", c.name, code, len(id), c.want)
		}
	}
}

func TestEpochGateBoundariesAccepted(t *testing.T) {
	f := newFixture(t)
	u := newUser()
	for _, iat := range []int64{f.window.Start, f.window.End - 1} {
		c := baseClaims(u)
		c["iat"] = iat
		if _, code := f.svc.Register(context.Background(), params(u, tok{claims: c}.mint(), "")); code != OK {
			t.Errorf("iat %d: %q", iat, code)
		}
	}
}

func TestGuestIDStableAcrossKeys(t *testing.T) {
	f := newFixture(t)
	sub := func(u *ecdsa.PrivateKey, phone string) string {
		c := baseClaims(u)
		c["phone_number"] = phone
		id, code := f.svc.Register(context.Background(), params(u, tok{claims: c}.mint(), ""))
		if code != OK {
			t.Fatal(code)
		}
		ct, _ := jose.ParseCompact(id)
		var p struct {
			Sub string `json:"sub"`
		}
		json.Unmarshal(ct.Payload, &p)
		return p.Sub
	}
	a, b := sub(newUser(), "15550001234"), sub(newUser(), "+15550001234")
	if a != b || a == sub(newUser(), "15550001235") {
		t.Error("guest ID not a stable function of the normalised phone")
	}
}

type unavailableKeys struct{}

func (unavailableKeys) Key(context.Context, string) (telegram.Key, error) {
	return telegram.Key{}, telegram.ErrUnavailable
}

func TestJWKSUnavailableIsInternal(t *testing.T) {
	f := newFixture(t)
	f.svc.tg = telegram.NewVerifier(unavailableKeys{}, clientID)
	u := newUser()
	if _, code := f.svc.Register(context.Background(), params(u, tok{claims: baseClaims(u)}.mint(), "")); code != Internal {
		t.Error(code)
	}
}
