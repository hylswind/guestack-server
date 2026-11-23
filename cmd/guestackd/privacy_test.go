//go:build dev

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/hylswind/guestack-server/internal/devclient"
	"github.com/hylswind/guestack-server/internal/epoch"
	"github.com/hylswind/guestack-server/internal/secret"
)

// TestPrivacy runs the real dev binary, registers through the real HPKE
// channel with sentinel phone numbers along every error path, and asserts
// that no phone number, id_token or S appears in stdout, stderr, any HTTP
// response, or any outer request/response bytes (spec/registration.md,
// "Privacy").
func TestPrivacy(t *testing.T) {
	bin := buildBinary(t, true, currentEpoch())
	key := make([]byte, 32)
	rand.Read(key)
	addr := freeAddr(t)

	cmd := exec.Command(bin)
	cmd.Env = []string{"GUESTACK_LISTEN_ADDR=" + addr, "GUESTACK_DEV_SECRET=" + hex.EncodeToString(key)}
	var stdout, stderr syncBuffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() { cmd.Wait(); close(exited) }()
	defer func() {
		select {
		case <-exited:
		default:
			cmd.Process.Kill()
		}
	}()
	waitHealthy(t, "http://"+addr)

	var mu sync.Mutex
	var observed [][]byte
	c := &devclient.Client{
		BaseURL: "http://" + addr,
		HTTP:    &http.Client{Timeout: 10 * time.Second},
		Pins:    devclient.DevPins(),
		Observe: func(b []byte) { mu.Lock(); observed = append(observed, b); mu.Unlock() },
	}
	ctx := context.Background()
	hpkePK, err := c.ChannelKey(ctx)
	if err != nil {
		t.Fatal("attestation:", err)
	}

	const sentinel = "15550009876"   // the phone number that must never leak
	const anonymous = "888012345678" // rejected by policy; must not leak either
	var tokens []string
	var inner [][]byte
	mint := func(tok devclient.IDToken) string {
		s := tok.Mint()
		tokens = append(tokens, s)
		return s
	}
	register := func(name, idToken string, user *ecdsa.PrivateKey, pop string, want string) string {
		t.Helper()
		identity, code, err := c.Register(ctx, hpkePK, idToken, user, pop)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		inner = append(inner, []byte(identity+code))
		if code != want {
			t.Errorf("%s: code %q, want %q", name, code, want)
		}
		return identity
	}

	w, _ := epoch.Parse(currentEpoch())
	expectedSub := secret.NewFromBytes(key).GuestID("+" + sentinel)

	// Success, then a returning user with a new key gets the same guest ID.
	u1 := devclient.NewUser()
	tok := mint(devclient.IDToken{Nonce: devclient.Nonce(u1), PhoneNumber: sentinel})
	id := register("ok", tok, u1, devclient.Pop(u1, tok), "")
	ident, err := devclient.VerifyIdentity(id, time.Now())
	if err != nil || ident.Sub != expectedSub || ident.Exp != w.End {
		t.Fatalf("identity: %+v %v (want sub %s exp %d)", ident, err, expectedSub, w.End)
	}
	u2 := devclient.NewUser()
	tok = mint(devclient.IDToken{Alg: "ES256", Nonce: devclient.Nonce(u2), PhoneNumber: "+" + sentinel})
	id = register("returning user, ES256", tok, u2, devclient.Pop(u2, tok), "")
	if ident2, err := devclient.VerifyIdentity(id, time.Now()); err != nil || ident2.Sub != expectedSub || ident2.Boot != ident.Boot {
		t.Errorf("returning user got a different guest ID or boot: %+v %v", ident2, err)
	}

	// Every error path, each carrying the sentinel.
	u := devclient.NewUser()
	other := devclient.NewUser()
	ph := sentinel
	cases := []struct {
		name string
		tok  devclient.IDToken
		pop  func(string) string
		want string
	}{
		{"wrong aud", devclient.IDToken{Aud: "1", Nonce: devclient.Nonce(u), PhoneNumber: ph}, nil, "id_token_invalid"},
		{"wrong iss", devclient.IDToken{Iss: "https://evil.example", Nonce: devclient.Nonce(u), PhoneNumber: ph}, nil, "id_token_invalid"},
		{"expired", devclient.IDToken{Iat: time.Now().Unix() - 120, Exp: time.Now().Unix() - 60, Nonce: devclient.Nonce(u), PhoneNumber: ph}, nil, "id_token_invalid"},
		{"nonce for another key", devclient.IDToken{Nonce: devclient.Nonce(other), PhoneNumber: ph}, nil, "key_binding_failed"},
		{"no nonce", devclient.IDToken{NoNonce: true, PhoneNumber: ph}, nil, "key_binding_failed"},
		{"pop over another token", devclient.IDToken{Nonce: devclient.Nonce(u), PhoneNumber: ph}, func(string) string { return devclient.Pop(u, "x.y.z") }, "pop_invalid"},
		{"pop by another key", devclient.IDToken{Nonce: devclient.Nonce(u), PhoneNumber: ph}, func(s string) string { return devclient.Pop(other, s) }, "pop_invalid"},
		{"iat before epoch", devclient.IDToken{Iat: w.Start - 1, Exp: time.Now().Unix() + 30, Nonce: devclient.Nonce(u), PhoneNumber: ph}, nil, "epoch_not_active"},
		{"phone not shared", devclient.IDToken{Nonce: devclient.Nonce(u)}, nil, "phone_not_shared"},
		{"anonymous number", devclient.IDToken{Nonce: devclient.Nonce(u), PhoneNumber: anonymous}, nil, "phone_not_allowed"},
		{"malformed phone", devclient.IDToken{Nonce: devclient.Nonce(u), PhoneNumber: sentinel + "x"}, nil, "id_token_invalid"},
	}
	for _, cs := range cases {
		s := mint(cs.tok)
		pop := devclient.Pop(u, s)
		if cs.pop != nil {
			pop = cs.pop(s)
		}
		register(cs.name, s, u, pop, cs.want)
	}

	// bad_request: params missing pop, carrying a sentinel token.
	s := mint(devclient.IDToken{Nonce: devclient.Nonce(u), PhoneNumber: ph})
	pt, _, err := c.Call(ctx, hpkePK, []byte(`{"method":"register","params":{"id_token":"`+s+`","jwk":{}}}`))
	if err != nil || string(pt) != `{"ok":false,"error":"bad_request"}` {
		t.Errorf("bad_request: %s %v", pt, err)
	}
	inner = append(inner, pt)
	// An unknown method.
	pt, _, _ = c.Call(ctx, hpkePK, []byte(`{"method":"`+sentinel+`","params":{}}`))
	if string(pt) != `{"ok":false,"error":"bad_request"}` {
		t.Errorf("unknown method: %s", pt)
	}
	inner = append(inner, pt)
	// A plaintext body carrying the sentinel, outside the channel.
	resp, err := http.Post("http://"+addr+"/rpc", "application/octet-stream", strings.NewReader(`{"phone":"`+sentinel+`"}`))
	if err != nil || resp.StatusCode != http.StatusBadRequest {
		t.Errorf("plaintext rpc: %v %v", resp, err)
	}
	var plain bytes.Buffer
	plain.ReadFrom(resp.Body)
	resp.Body.Close()
	inner = append(inner, plain.Bytes())

	// Stop and collect.
	cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-exited:
	case <-time.After(15 * time.Second):
		t.Fatal("did not stop")
	}

	needles := map[string][]byte{
		"sentinel phone":  []byte(sentinel),
		"anonymous phone": []byte(anonymous),
		"S (raw)":         key,
		"S (hex)":         []byte(hex.EncodeToString(key)),
		"S (base64)":      []byte(base64.StdEncoding.EncodeToString(key)),
		"S (b64u)":        []byte(base64.RawURLEncoding.EncodeToString(key)),
	}
	for i, tk := range tokens {
		needles["id_token "+strconv.Itoa(i)] = []byte(tk)
		needles["id_token signature "+strconv.Itoa(i)] = []byte(tk[strings.LastIndex(tk, ".")+1:])
	}
	haystacks := map[string][]byte{"stdout": stdout.Bytes(), "stderr": stderr.Bytes()}
	for i, b := range observed {
		haystacks["outer bytes "+strconv.Itoa(i)] = b
	}
	for i, b := range inner {
		haystacks["inner response "+strconv.Itoa(i)] = b
	}
	for hn, h := range haystacks {
		for nn, n := range needles {
			if bytes.Contains(h, n) {
				t.Errorf("%s contains %s", hn, nn)
			}
		}
	}
	if len(observed) < 2*len(cases) {
		t.Errorf("only %d outer messages observed", len(observed))
	}
	assertOnlySafeLines(t, stdout.String())
	assertOnlySafeLines(t, stderr.String())
	for _, ev := range []string{"event=started", "event=stopped", "register_ok=2"} {
		if !strings.Contains(stderr.String(), ev) {
			t.Errorf("stderr lacks %s: %q", ev, stderr.String())
		}
	}
}

// currentEpoch is the UTC month now, so dev tokens with iat = now pass the gate.
func currentEpoch() string { return time.Now().UTC().Format("2006-01") }

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func waitHealthy(t *testing.T, base string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(base + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("backend did not become healthy")
}

// syncBuffer is a bytes.Buffer safe for the exec package's copy goroutine.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.b.Bytes()...)
}

func (s *syncBuffer) String() string { return string(s.Bytes()) }
