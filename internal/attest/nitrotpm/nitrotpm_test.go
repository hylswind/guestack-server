package nitrotpm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hylswind/guestack-server/internal/attest"
)

// The test binary doubles as a fake nitro-tpm-attest. It receives no
// environment, so the request it should play comes in through user_data.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "--user-data" {
		os.Exit(fakeTool())
	}
	os.Exit(m.Run())
}

type fakeRequest struct {
	Mode string `json:"mode"`
	Dir  string `json:"dir"`
}

type fakeCall struct {
	Args []string `json:"args"`
	Env  []string `json:"env"`
}

func fakeTool() int {
	userData, err := os.ReadFile(os.Args[2])
	if err != nil {
		return 1
	}
	var req fakeRequest
	if err := json.Unmarshal(userData, &req); err != nil {
		return 1
	}
	call, _ := json.Marshal(fakeCall{os.Args[1:], os.Environ()})
	f, err := os.OpenFile(filepath.Join(req.Dir, "calls"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return 1
	}
	fmt.Fprintf(f, "%s\n", call)
	f.Close()
	fmt.Fprintln(os.Stderr, "free text from the tool")

	switch req.Mode {
	case "busy":
		return exitTemporary
	case "busy-once":
		marker := filepath.Join(req.Dir, "busy")
		if _, err := os.Stat(marker); err != nil {
			os.WriteFile(marker, nil, 0o600)
			return exitTemporary
		}
	case "fail":
		return 1
	case "empty":
		return 0
	case "oversize":
		os.Stdout.Write(make([]byte, maxDocumentSize+1))
		return 0
	case "max-size":
		os.Stdout.Write(make([]byte, maxDocumentSize))
		return 0
	}
	os.Stdout.Write(append([]byte("document:"), userData...))
	return 0
}

func setup(t *testing.T, mode string) (*Provider, []byte, func() []fakeCall) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	userData, err := json.Marshal(fakeRequest{mode, dir})
	if err != nil {
		t.Fatal(err)
	}
	calls := func() []fakeCall {
		data, err := os.ReadFile(filepath.Join(dir, "calls"))
		if err != nil {
			t.Fatal(err)
		}
		var out []fakeCall
		for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
			var c fakeCall
			if err := json.Unmarshal(line, &c); err != nil {
				t.Fatal(err)
			}
			out = append(out, c)
		}
		return out
	}
	return &Provider{tool: self, delay: time.Millisecond}, userData, calls
}

func TestNewUsesTheToolInTheImage(t *testing.T) {
	if p := New(); p.tool != "/usr/bin/nitro-tpm-attest" || p.delay != time.Second {
		t.Errorf("provider = %+v", p)
	}
}

func TestDocument(t *testing.T) {
	t.Setenv("TPM_RESOURCE_MANAGER_DEVICE", "/dev/operator-chosen")
	p, userData, calls := setup(t, "ok")
	doc, err := p.Document(context.Background(), userData)
	if err != nil {
		t.Fatal(err)
	}
	if want := append([]byte("document:"), userData...); !bytes.Equal(doc, want) {
		t.Errorf("document = %q, want %q", doc, want)
	}
	got := calls()
	if len(got) != 1 {
		t.Fatalf("%d calls", len(got))
	}
	if len(got[0].Args) != 2 || got[0].Args[0] != "--user-data" || got[0].Args[1] != "/dev/stdin" {
		t.Errorf("args = %q", got[0].Args)
	}
	if len(got[0].Env) != 0 {
		t.Errorf("the tool received an environment: %q", got[0].Env)
	}
}

func TestDocumentRetriesATemporaryFailure(t *testing.T) {
	p, userData, calls := setup(t, "busy-once")
	if _, err := p.Document(context.Background(), userData); err != nil {
		t.Fatal(err)
	}
	if n := len(calls()); n != 2 {
		t.Errorf("%d calls, want 2", n)
	}
}

func TestDocumentGivesUpAfterMaxAttempts(t *testing.T) {
	p, userData, calls := setup(t, "busy")
	if _, err := p.Document(context.Background(), userData); !errors.Is(err, attest.ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
	if n := len(calls()); n != maxAttempts {
		t.Errorf("%d calls, want %d", n, maxAttempts)
	}
}

func TestDocumentFailures(t *testing.T) {
	for _, mode := range []string{"fail", "empty", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			p, userData, calls := setup(t, mode)
			doc, err := p.Document(context.Background(), userData)
			if err != attest.ErrUnavailable || doc != nil {
				t.Fatalf("doc = %d bytes, err = %v", len(doc), err)
			}
			if n := len(calls()); n != 1 {
				t.Errorf("%d calls, want 1: only a temporary failure is retried", n)
			}
		})
	}
}

func TestDocumentAcceptsTheMaximumSize(t *testing.T) {
	p, userData, _ := setup(t, "max-size")
	doc, err := p.Document(context.Background(), userData)
	if err != nil || len(doc) != maxDocumentSize {
		t.Fatalf("doc = %d bytes, err = %v", len(doc), err)
	}
}

func TestDocumentToolMissing(t *testing.T) {
	p := &Provider{tool: filepath.Join(t.TempDir(), "missing"), delay: time.Millisecond}
	if _, err := p.Document(context.Background(), []byte("x")); err != attest.ErrUnavailable {
		t.Fatalf("err = %v", err)
	}
}

func TestDocumentStopsRetryingWhenCancelled(t *testing.T) {
	p, userData, calls := setup(t, "busy")
	p.delay = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := p.Document(ctx, userData)
		done <- err
	}()
	// The first attempt runs, then the provider waits out its delay.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(fakeDir(t, userData), "calls")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the tool did not run")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != attest.ErrUnavailable {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Document did not return after cancellation")
	}
	if n := len(calls()); n != 1 {
		t.Errorf("%d calls, want 1", n)
	}
}

func fakeDir(t *testing.T, userData []byte) string {
	t.Helper()
	var req fakeRequest
	if err := json.Unmarshal(userData, &req); err != nil {
		t.Fatal(err)
	}
	return req.Dir
}
