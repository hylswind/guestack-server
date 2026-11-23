// Package vectors loads and (with -update-vectors) rewrites the test vectors
// in spec/vectors. It is imported only by tests.
//
// Each vector file is checked by the package that implements it. Regenerate
// with:
//
//	go test ./... -run Vectors -update-vectors
//
// Deterministic vectors regenerate identically. Vectors that contain a fresh
// signature or HPKE encapsulation change on every regeneration, so only
// regenerate them when the format itself changes.
package vectors

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update-vectors", false, "rewrite spec/vectors from the implementation")

// Update reports whether -update-vectors was given.
func Update() bool { return *update }

// Path returns the absolute path of spec/vectors/<name>.
func Path(t testing.TB, name string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, "spec", "vectors", name)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

// Load decodes spec/vectors/<name> into v, rejecting unknown fields.
func Load(t testing.TB, name string, v any) {
	t.Helper()
	data, err := os.ReadFile(Path(t, name))
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

// FixedP256 returns a deterministic P-256 key whose scalar is SHA-256(label).
// Test-only: these keys are published in the vector files.
func FixedP256(t testing.TB, label string) *ecdsa.PrivateKey {
	t.Helper()
	d := sha256.Sum256([]byte(label))
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d[:])
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// Write encodes v into spec/vectors/<name> (2-space indent, no HTML escaping).
func Write(t testing.TB, name string, v any) {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(Path(t, name), buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote spec/vectors/%s", name)
}
