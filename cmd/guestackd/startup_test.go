package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The production binary fails closed: every misconfiguration exits non-zero
// with a fixed event, and it cannot start at all until NitroTPM attestation
// is implemented.
func TestProductionStartupFailsClosed(t *testing.T) {
	bin := buildBinary(t, false, "2026-12")
	noEpoch := buildBinary(t, false, "")
	for _, c := range []struct {
		name, bin string
		env       []string
		event     string
	}{
		{"no epoch compiled in", noEpoch, nil, "event=epoch_invalid"},
		// Off EC2 there is no instance metadata service, so no region.
		{"no instance metadata service", bin, nil, "event=signer_unavailable"},
	} {
		code, out := runToExit(t, c.bin, c.env)
		if code == 0 || !strings.Contains(out, c.event) {
			t.Errorf("%s: exit %d, output %q", c.name, code, out)
		}
		assertOnlySafeLines(t, out)
	}
}

// The production binary must contain nothing from the dev build: no dev
// packages, no dev keys, no dev configuration, no dev build tag. The same
// scan of the dev binary must find them, so the check itself is meaningful.
func TestProductionBinaryHasNoDevSymbols(t *testing.T) {
	markers := []string{
		"internal/devkeys",
		"internal/attest/devfake",
		"internal/devclient",
		"GUESTACK-DEV-BUILD-NOT-FOR-PRODUCTION",
		"GUESTACK_DEV_SECRET",
		"BEGIN PRIVATE KEY",
		"dev-rs256-1",
		"GUESTACK_", // the production binary has no environment variable names at all
	}
	check := func(bin string, wantPresent bool) {
		data, err := os.ReadFile(bin)
		if err != nil {
			t.Fatal(err)
		}
		found := 0
		for _, m := range markers {
			has := bytes.Contains(data, []byte(m))
			if has {
				found++
			}
			if has && !wantPresent {
				t.Errorf("production binary contains %q", m)
			}
		}
		if wantPresent && found < 5 {
			t.Errorf("dev binary contains only %d markers; the scan is not meaningful", found)
		}
		info, err := exec.Command("go", "version", "-m", bin).Output()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(info), "-tags=dev") != wantPresent {
			t.Errorf("build info tags for %s: %s", bin, info)
		}
	}
	check(buildBinary(t, false, "2026-12"), false)
	check(buildBinary(t, true, "2026-12"), true)
}

// envFuncs are the functions that read the process environment.
var envFuncs = map[string]map[string]bool{
	"os":      {"Getenv": true, "LookupEnv": true, "Environ": true, "ExpandEnv": true},
	"syscall": {"Getenv": true, "Environ": true},
}

// envReads lists every call of an envFuncs function in this module's
// non-test source files that a build with the given tags compiles.
func envReads(t *testing.T, tags string) []string {
	t.Helper()
	args := []string{"list", "-deps", "-f", "{{.ImportPath}}\t{{.Dir}}\t{{join .GoFiles \",\"}}"}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	out, err := exec.Command("go", append(args, ".")...).Output()
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 3 || !strings.HasPrefix(f[0], "github.com/hylswind/guestack-server/") || f[2] == "" {
			continue
		}
		for _, name := range strings.Split(f[2], ",") {
			path := filepath.Join(f[1], name)
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
			if err != nil {
				t.Fatal(err)
			}
			local := map[string]string{} // local import name → package path
			for _, imp := range file.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				if envFuncs[p] == nil {
					continue
				}
				n := p
				if imp.Name != nil {
					n = imp.Name.Name
				}
				local[n] = p
			}
			ast.Inspect(file, func(n ast.Node) bool {
				if sel, ok := n.(*ast.SelectorExpr); ok {
					if id, ok := sel.X.(*ast.Ident); ok && envFuncs[local[id.Name]][sel.Sel.Name] {
						found = append(found, path+": "+local[id.Name]+"."+sel.Sel.Name)
					}
				}
				return true
			})
		}
	}
	return found
}

// TestProductionReadsNoEnvironment: the backend has no runtime
// configuration. No code of this module that the production build compiles
// reads the environment. Third-party and standard library reads are covered
// in spec/external-notes.md, "No runtime configuration". The same scan of
// the dev build must find the dev-only reads, so the check is meaningful.
func TestProductionReadsNoEnvironment(t *testing.T) {
	if found := envReads(t, ""); len(found) != 0 {
		t.Errorf("production code reads the environment:\n%s", strings.Join(found, "\n"))
	}
	if found := envReads(t, "dev"); len(found) == 0 {
		t.Error("the scan found no environment reads in the dev build; it is not working")
	}
}
