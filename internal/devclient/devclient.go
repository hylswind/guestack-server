//go:build dev

// Package devclient plays the login page's part against a dev backend: verify the
// attestation, mint a dev Telegram id_token, build pop, call register over
// HPKE, and check the identity token. It is the Go reference for the login page
// and is used by the privacy test and cmd/devclient.
package devclient

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hylswind/guestack-server/internal/binding"
	"github.com/hylswind/guestack-server/internal/channel"
	"github.com/hylswind/guestack-server/internal/devkeys"
	"github.com/hylswind/guestack-server/internal/jose"
	"github.com/hylswind/guestack-server/internal/telegram"
)

// DevPins are the pins a test copy of the login page uses against a dev backend:
// the dev root and PCR4, PCR7, PCR12.
func DevPins() Pins {
	root, _ := devkeys.NitroRoot()
	all := devkeys.PCRs()
	return Pins{
		RootSHA256: sha256.Sum256(root.Raw),
		PCRs:       map[int][]byte{4: all[4], 7: all[7], 12: all[12]},
	}
}

// Client talks to a backend.
type Client struct {
	BaseURL string // e.g. http://127.0.0.1:8080/
	HTTP    *http.Client
	Pins    Pins
	// Observe, if set, receives every outer request and response body.
	Observe func(b []byte)
}

// ChannelKey fetches and verifies GET /attestation and returns hpke_pk.
func (c *Client) ChannelKey(ctx context.Context) ([]byte, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.url("attestation"), nil)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, ErrAttestation
	}
	c.observe(body)
	var v struct {
		Doc    string `json:"doc"`
		HPKEPK string `json:"hpke_pk"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return nil, ErrAttestation
	}
	doc, err1 := base64.StdEncoding.DecodeString(v.Doc)
	pk, err2 := jose.DecodeB64(v.HPKEPK)
	if err1 != nil || err2 != nil {
		return nil, ErrAttestation
	}
	if err := VerifyAttestation(doc, pk, c.Pins, time.Now()); err != nil {
		return nil, err
	}
	return pk, nil
}

// Call sends an inner request over the channel and returns the inner
// response, or the HTTP status when the backend answered outside the channel.
func (c *Client) Call(ctx context.Context, hpkePK, inner []byte) ([]byte, int, error) {
	msg, pending, err := channel.SealRequest(hpkePK, inner)
	if err != nil {
		return nil, 0, err
	}
	c.observe(msg)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.url("rpc"), bytes.NewReader(msg))
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, 0, err
	}
	c.observe(body)
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, nil
	}
	pt, err := pending.OpenResponse(body)
	return pt, resp.StatusCode, err
}

// Register calls register and returns the identity token, or the error code.
func (c *Client) Register(ctx context.Context, hpkePK []byte, idToken string, user *ecdsa.PrivateKey, pop string) (string, string, error) {
	jwk, err := jose.NewP256JWK(&user.PublicKey)
	if err != nil {
		return "", "", err
	}
	j, _ := jwk.MarshalJSON()
	inner := `{"method":"register","params":{"id_token":` + jose.MarshalString(idToken) +
		`,"jwk":` + string(j) + `,"pop":` + jose.MarshalString(pop) + `}}`
	pt, status, err := c.Call(ctx, hpkePK, []byte(inner))
	if err != nil {
		return "", "", err
	}
	if status != http.StatusOK {
		return "", "", errors.New("HTTP " + strconv.Itoa(status))
	}
	var r struct {
		OK     bool   `json:"ok"`
		Error  string `json:"error"`
		Result struct {
			Identity string `json:"identity"`
		} `json:"result"`
	}
	if err := json.Unmarshal(pt, &r); err != nil {
		return "", "", err
	}
	if !r.OK {
		return "", r.Error, nil
	}
	return r.Result.Identity, "", nil
}

func (c *Client) url(path string) string { return strings.TrimSuffix(c.BaseURL, "/") + "/" + path }

func (c *Client) observe(b []byte) {
	if c.Observe != nil {
		c.Observe(append([]byte(nil), b...))
	}
}

// NewUser generates a user key (the login page uses a non-extractable WebCrypto key).
func NewUser() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}

// Nonce is the nonce the login page passes to Telegram for this user key.
func Nonce(user *ecdsa.PrivateKey) string {
	jwk, _ := jose.NewP256JWK(&user.PublicKey)
	return binding.Nonce(jwk)
}

// Pop builds the pop JWS.
func Pop(user *ecdsa.PrivateKey, idToken string) string {
	return SignJWS(user, `{"alg":"ES256","typ":"guestack-reg+jwt"}`, `{"h":"`+binding.PopHash(idToken)+`"}`)
}

// SignJWS signs literal header and payload JSON with an ECDSA P-256 key.
func SignJWS(k *ecdsa.PrivateKey, header, payload string) string {
	input := jose.B64([]byte(header)) + "." + jose.B64([]byte(payload))
	sig, err := jose.SignES256(k, input)
	if err != nil {
		panic(err)
	}
	return input + "." + jose.B64(sig)
}

// IDToken describes a dev Telegram id_token. Zero values get defaults:
// Alg RS256, Iss telegram.Issuer, Aud the dev client ID, Iat now, Exp Iat+30.
type IDToken struct {
	Alg         string
	Iss         string
	Aud         string
	Iat, Exp    int64
	Nonce       string
	NoNonce     bool
	PhoneNumber string // empty: no phone_number claim
	Extra       map[string]any
}

// Mint signs a dev Telegram id_token with the dev Telegram keys.
func (t IDToken) Mint() string {
	now := time.Now().Unix()
	if t.Alg == "" {
		t.Alg = "RS256"
	}
	if t.Iss == "" {
		t.Iss = telegram.Issuer
	}
	if t.Aud == "" {
		t.Aud = strconv.FormatInt(devkeys.TelegramClientID, 10)
	}
	if t.Iat == 0 {
		t.Iat = now
	}
	if t.Exp == 0 {
		t.Exp = t.Iat + 30
	}
	claims := map[string]any{
		"iss": t.Iss, "aud": t.Aud, "sub": "1234567890123456789", "iat": t.Iat, "exp": t.Exp,
		"id": 987654321, "name": "Dev User",
	}
	if !t.NoNonce {
		claims["nonce"] = t.Nonce
	}
	if t.PhoneNumber != "" {
		claims["phone_number"] = t.PhoneNumber
		claims["phone_number_verified"] = true
	}
	for k, v := range t.Extra {
		claims[k] = v
	}
	payload, _ := json.Marshal(claims)
	kid := devkeys.TelegramRS256Kid
	if t.Alg == "ES256" {
		kid = devkeys.TelegramES256Kid
	}
	header := `{"alg":"` + t.Alg + `","kid":"` + kid + `","typ":"JWT"}`
	input := jose.B64([]byte(header)) + "." + jose.B64(payload)
	digest := sha256.Sum256([]byte(input))
	var sig []byte
	switch t.Alg {
	case "ES256":
		sig, _ = jose.SignES256(devkeys.TelegramES256(), input)
	default:
		sig, _ = rsa.SignPKCS1v15(rand.Reader, devkeys.TelegramRS256(), crypto.SHA256, digest[:])
	}
	return input + "." + jose.B64(sig)
}

// Identity is a verified identity token's payload.
type Identity struct {
	Sub  string
	Exp  int64
	Boot string
	Cnf  *jose.P256JWK
}

var uuidV8 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// VerifyIdentity checks an identity token against the dev issuer key the
// way an RP does (spec/identity-token.md, "Verification by RPs").
func VerifyIdentity(token string, now time.Time) (*Identity, error) {
	bad := errors.New("identity token invalid")
	c, err := jose.ParseCompact(token)
	if err != nil {
		return nil, bad
	}
	issPub := &devkeys.Issuer().PublicKey
	issJWK, _ := jose.NewP256JWK(issPub)
	tp := issJWK.Thumbprint()
	var hdr struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}
	if jose.DecodeJSON(c.Header, &hdr) != nil || hdr.Alg != "ES256" || hdr.Typ != "guestack-id+jwt" || hdr.Kid != jose.B64(tp[:]) {
		return nil, bad
	}
	if jose.VerifyES256(issPub, c.SigningInput, c.Signature) != nil {
		return nil, bad
	}
	var p struct {
		Iss  string `json:"iss"`
		Sub  string `json:"sub"`
		Exp  int64  `json:"exp"`
		Boot string `json:"boot"`
		Cnf  struct {
			JWK json.RawMessage `json:"jwk"`
		} `json:"cnf"`
	}
	if jose.DecodeJSON(c.Payload, &p) != nil || p.Iss != "guestack" || !uuidV8.MatchString(p.Sub) || now.Unix() >= p.Exp+60 {
		return nil, bad
	}
	jwk, err := jose.ParseP256JWK(p.Cnf.JWK)
	if err != nil {
		return nil, bad
	}
	return &Identity{Sub: p.Sub, Exp: p.Exp, Boot: p.Boot, Cnf: jwk}, nil
}
