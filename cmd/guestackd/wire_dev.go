//go:build dev

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"os"

	"github.com/hylswind/guestack-server/internal/attest/devfake"
	"github.com/hylswind/guestack-server/internal/devkeys"
	"github.com/hylswind/guestack-server/internal/safelog"
	"github.com/hylswind/guestack-server/internal/secret"
	"github.com/hylswind/guestack-server/internal/telegram"
)

type localSigner struct{ priv *ecdsa.PrivateKey }

// SignDigest returns DER, like KMS, so the DER→raw path is always exercised.
func (s localSigner) SignDigest(_ context.Context, d [32]byte) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, s.priv, d[:])
}

// buildDeps wires the dev components: devfake attestation, the dev issuer
// key, and the dev Telegram keys (no network).
//
// Unlike the production build, the dev build reads two environment
// variables, both only here:
//   - GUESTACK_LISTEN_ADDR (default 127.0.0.1:8080), so tests can pick a port;
//   - GUESTACK_DEV_SECRET (64 hex chars), which fixes S so that the privacy
//     test knows what must never appear in output.
func buildDeps(_ context.Context) (*deps, safelog.Event, bool) {
	addr := os.Getenv("GUESTACK_LISTEN_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	s := secret.New()
	if v := os.Getenv("GUESTACK_DEV_SECRET"); v != "" {
		key, err := hex.DecodeString(v)
		if err != nil || len(key) != 32 {
			return nil, safelog.ConfigInvalid, false
		}
		s = secret.NewFromBytes(key)
	}
	iss := devkeys.Issuer()
	tgES := devkeys.TelegramES256()
	return &deps{
		listenAddr: addr,
		attest:     devfake.New(),
		signer:     localSigner{iss},
		issuerPub:  &iss.PublicKey,
		keys: telegram.StaticKeys{
			devkeys.TelegramRS256Kid: {Alg: "RS256", Pub: &devkeys.TelegramRS256().PublicKey},
			devkeys.TelegramES256Kid: {Alg: "ES256", Pub: &tgES.PublicKey},
		},
		clientID: devkeys.TelegramClientID,
		secret:   s,
	}, safelog.Event{}, true
}
