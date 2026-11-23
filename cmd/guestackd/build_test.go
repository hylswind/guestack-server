package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// Helpers shared by the binary-level tests. They build guestackd exactly as
// the Makefile does.

var (
	buildMu    sync.Mutex
	buildCache = map[string]string{}
	buildDir   string
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "guestackd-test-")
	if err != nil {
		panic(err)
	}
	buildDir = dir
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// buildBinary builds guestackd once per (dev, epochID) and returns its path.
func buildBinary(t *testing.T, dev bool, epochID string) string {
	t.Helper()
	if testing.Short() {
		t.Skip("builds the binary")
	}
	key := strings.Join([]string{map[bool]string{true: "dev", false: "prod"}[dev], epochID}, "-")
	buildMu.Lock()
	defer buildMu.Unlock()
	if p, ok := buildCache[key]; ok {
		return p
	}
	out := filepath.Join(buildDir, "guestackd-"+key)
	args := []string{"build", "-trimpath", "-buildvcs=false",
		"-ldflags", "-s -w -X github.com/hylswind/guestack-server/internal/epoch.ID=" + epochID,
		"-o", out}
	if dev {
		args = append(args, "-tags", "dev")
	}
	args = append(args, ".")
	cmd := exec.Command("go", args...)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, b)
	}
	buildCache[key] = out
	return out
}

// runToExit runs a binary with exactly env and returns its exit code and output.
func runToExit(t *testing.T, bin string, env []string) (int, string) {
	t.Helper()
	cmd := exec.Command(bin)
	cmd.Env = env
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		cmd.Process.Kill()
		t.Fatal("binary did not exit")
	}
	return cmd.ProcessState.ExitCode(), out.String()
}

// logLine is the only shape guestackd may print.
var logLine = regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ guestackd (event=[a-z_]+|counters( [a-z_]+=\d+)+)$`)

func assertOnlySafeLines(t *testing.T, out string) {
	t.Helper()
	for _, l := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if l != "" && !logLine.MatchString(l) {
			t.Errorf("unexpected output line: %q", l)
		}
	}
}
