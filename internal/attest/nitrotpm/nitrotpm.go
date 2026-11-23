// Package nitrotpm requests attestation documents from the instance's
// NitroTPM through nitro-tpm-attest, the AWS tool shipped in the measured
// image. The channel key goes in as user_data.
package nitrotpm

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"time"

	"github.com/hylswind/guestack-server/internal/attest"
)

const (
	toolPath = "/usr/bin/nitro-tpm-attest"

	// maxDocumentSize bounds what is read from the tool. A document holds a
	// few certificates and the PCRs, a few KiB in total.
	maxDocumentSize = 64 << 10

	// exitTemporary is the exit code of nitro-tpm-attest 2.0 and later for a
	// TPM that is busy or short of NV memory, where repeating the request can
	// succeed. Earlier versions exit 1, which is not retried.
	exitTemporary = 75
	maxAttempts   = 5
	retryDelay    = time.Second

	// waitDelay limits how long a cancelled request waits for the tool's pipes.
	waitDelay = 5 * time.Second
)

var (
	errBusy   = errors.New("nitrotpm: temporarily unavailable")
	errFailed = errors.New("nitrotpm: request failed")
	errTooBig = errors.New("nitrotpm: document too large")
)

// Provider is the production attestation provider.
type Provider struct {
	tool  string
	delay time.Duration
}

// New returns the provider. Whether the TPM works shows on the first
// Document call, and startup fails if that call fails.
func New() *Provider { return &Provider{tool: toolPath, delay: retryDelay} }

// Document implements attest.Provider. Every failure is attest.ErrUnavailable.
func (p *Provider) Document(ctx context.Context, userData []byte) ([]byte, error) {
	for attempt := 1; ; attempt++ {
		doc, err := p.request(ctx, userData)
		if err == nil {
			return doc, nil
		}
		if !errors.Is(err, errBusy) || attempt == maxAttempts {
			return nil, attest.ErrUnavailable
		}
		select {
		case <-ctx.Done():
			return nil, attest.ErrUnavailable
		case <-time.After(p.delay):
		}
	}
}

// request runs the tool once. user_data arrives on standard input, so
// nothing is written to disk. The environment is empty because the tool reads
// the TPM device paths from it, and the backend has no runtime configuration.
// Standard error stays unread: it is free text and must not reach the logs.
func (p *Provider) request(ctx context.Context, userData []byte) ([]byte, error) {
	var out cappedBuffer
	cmd := exec.CommandContext(ctx, p.tool, "--user-data", "/dev/stdin")
	cmd.Env = []string{}
	cmd.Stdin = bytes.NewReader(userData)
	cmd.Stdout = &out
	cmd.WaitDelay = waitDelay

	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == exitTemporary {
		return nil, errBusy
	}
	if err != nil || out.buf.Len() == 0 {
		return nil, errFailed
	}
	return out.buf.Bytes(), nil
}

// cappedBuffer fails a write that would exceed maxDocumentSize.
type cappedBuffer struct{ buf bytes.Buffer }

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.buf.Len()+len(p) > maxDocumentSize {
		return 0, errTooBig
	}
	return b.buf.Write(p)
}
