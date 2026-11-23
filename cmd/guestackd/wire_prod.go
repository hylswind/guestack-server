//go:build !dev

package main

import (
	"context"

	"github.com/hylswind/guestack-server/internal/attest/nitrotpm"
	"github.com/hylswind/guestack-server/internal/issuer/kmssigner"
	"github.com/hylswind/guestack-server/internal/safelog"
	"github.com/hylswind/guestack-server/internal/secret"
	"github.com/hylswind/guestack-server/internal/telegram"
)

// listenAddr is compiled in (there is no runtime configuration). Only the
// internal proxy can reach it.
const listenAddr = ":8080"

// buildDeps wires the production components. On failure it returns the
// event to log.
func buildDeps(ctx context.Context) (*deps, safelog.Event, bool) {
	if telegram.ClientID == 0 {
		return nil, safelog.TelegramClientIDUnset, false
	}
	api, err := kmssigner.NewClient(ctx)
	if err != nil {
		return nil, safelog.SignerUnavailable, false
	}
	signer, pub, err := kmssigner.New(ctx, api, kmssigner.KeyAlias)
	if err != nil {
		return nil, safelog.SignerUnavailable, false
	}
	provider, err := nitrotpm.New()
	if err != nil {
		return nil, safelog.AttestationUnavailable, false
	}
	return &deps{
		listenAddr: listenAddr,
		attest:     provider,
		signer:     signer,
		issuerPub:  pub,
		keys:       telegram.NewFetcher(),
		clientID:   telegram.ClientID,
		secret:     secret.New(),
	}, safelog.Event{}, true
}
