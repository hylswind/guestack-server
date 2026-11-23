// Command guestackd is the Guestack backend.
//
// Build (EPOCH_ID is compiled in and therefore measured):
//
//	CGO_ENABLED=0 go build -trimpath \
//	  -ldflags "-s -w -X github.com/hylswind/guestack-server/internal/epoch.ID=2026-12" ./cmd/guestackd
//
// The production binary has no runtime configuration: it reads no
// environment variable and no configuration file. The listen address and the
// KMS key alias are compiled in; the AWS region comes from the instance
// metadata service.
//
// The dev build (-tags dev) replaces attestation, the issuer key and
// Telegram's keys with the throwaway material of internal/devkeys, and reads
// two dev-only environment variables (see wire_dev.go).
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/hylswind/guestack-server/internal/api"
	"github.com/hylswind/guestack-server/internal/attest"
	"github.com/hylswind/guestack-server/internal/channel"
	"github.com/hylswind/guestack-server/internal/epoch"
	"github.com/hylswind/guestack-server/internal/issuer"
	"github.com/hylswind/guestack-server/internal/jose"
	"github.com/hylswind/guestack-server/internal/registration"
	"github.com/hylswind/guestack-server/internal/safelog"
	"github.com/hylswind/guestack-server/internal/secret"
	"github.com/hylswind/guestack-server/internal/telegram"
)

// deps are the components that differ between the production and dev builds.
type deps struct {
	listenAddr string
	attest     attest.Provider
	signer     issuer.Signer
	issuerPub  *ecdsa.PublicKey
	keys       telegram.KeySet
	clientID   int64
	secret     *secret.Secret
}

func main() { os.Exit(run()) }

func run() int {
	// An unrecovered panic prints only its message, no goroutine stacks.
	// Every goroutine and handler recovers through safelog anyway.
	debug.SetTraceback("none")

	window, err := epoch.Compiled()
	if err != nil {
		safelog.Log(safelog.EpochInvalid)
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	d, ev, ok := buildDeps(ctx)
	if !ok {
		safelog.Log(ev)
		return 1
	}
	keys, err := channel.Generate()
	if err != nil {
		safelog.Log(safelog.StartupFailed)
		return 1
	}
	cache, err := attest.NewCache(ctx, d.attest, keys.PublicKey())
	if err != nil {
		safelog.Log(safelog.AttestationUnavailable)
		return 1
	}
	iss, err := issuer.New(d.signer, d.issuerPub)
	if err != nil {
		safelog.Log(safelog.SignerUnavailable)
		return 1
	}
	var boot [8]byte
	rand.Read(boot[:])
	reg := registration.New(telegram.NewVerifier(d.keys, d.clientID), d.secret, iss, window, jose.B64(boot[:]))

	ln, err := net.Listen("tcp", d.listenAddr)
	if err != nil {
		safelog.Log(safelog.ListenFailed)
		return 1
	}
	srv := &http.Server{
		Handler:           api.New(keys, cache, reg).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8192,
		// net/http's own messages (TLS errors, malformed requests) could echo
		// request bytes; they are discarded.
		ErrorLog: log.New(io.Discard, "", 0),
	}

	go safelog.Go(func() { cache.Run(ctx) })
	go safelog.Go(func() { safelog.ReportCounters(ctx, 5*time.Minute) })
	serveErr := make(chan error, 1)
	go safelog.Go(func() { serveErr <- srv.Serve(ln) })
	safelog.Log(safelog.Started)

	code := 0
	select {
	case <-ctx.Done():
	case <-serveErr:
		safelog.Log(safelog.ListenFailed)
		code = 1
	}
	safelog.Log(safelog.Stopping)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(shutdownCtx)
	safelog.LogCounters()
	safelog.Log(safelog.Stopped)
	return code
}
