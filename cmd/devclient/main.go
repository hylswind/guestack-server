//go:build dev

// Command devclient runs one registration against a dev backend, doing the
// login page's part: verify the attestation, mint a dev Telegram id_token bound to
// a fresh user key, send register over HPKE, and verify the identity token.
//
//	make run-dev                                  # in one terminal
//	go run -tags dev ./cmd/devclient -phone 15550001234
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/hylswind/guestack-server/internal/devclient"
	"github.com/hylswind/guestack-server/internal/jose"
)

func main() {
	base := flag.String("base", "http://127.0.0.1:8080/", "API base of a dev backend")
	phone := flag.String("phone", "15550001234", "phone_number claim of the dev id_token")
	alg := flag.String("alg", "RS256", "dev Telegram signing algorithm: RS256 or ES256")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := &devclient.Client{BaseURL: *base, HTTP: &http.Client{Timeout: 10 * time.Second}, Pins: devclient.DevPins()}

	hpkePK, err := c.ChannelKey(ctx)
	if err != nil {
		fail("attestation: %v", err)
	}
	fmt.Println("attestation verified; hpke_pk", jose.B64(hpkePK))

	user := devclient.NewUser()
	tok := devclient.IDToken{Alg: *alg, Nonce: devclient.Nonce(user), PhoneNumber: *phone}.Mint()
	identity, code, err := c.Register(ctx, hpkePK, tok, user, devclient.Pop(user, tok))
	if err != nil {
		fail("register: %v", err)
	}
	if code != "" {
		fail("register: error code %s", code)
	}
	id, err := devclient.VerifyIdentity(identity, time.Now())
	if err != nil {
		fail("identity token: %v", err)
	}
	out, _ := json.MarshalIndent(map[string]any{
		"identity": identity, "sub": id.Sub, "exp": time.Unix(id.Exp, 0).UTC().Format(time.RFC3339), "boot": id.Boot,
	}, "", "  ")
	fmt.Println(string(out))
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "devclient: "+format+"\n", a...)
	os.Exit(1)
}
