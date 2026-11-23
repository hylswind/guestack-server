package safelog

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestPanicValueNeverPrinted(t *testing.T) {
	var buf bytes.Buffer
	SetOutput(&buf)
	defer SetOutput(os.Stderr)
	before := Panics.Value()
	Go(func() { panic("+15550001234 sentinel") })
	if Panics.Value() != before+1 {
		t.Error("panic not counted")
	}
	out := buf.String()
	if strings.Contains(out, "sentinel") || strings.Contains(out, "1555") {
		t.Errorf("panic value leaked: %q", out)
	}
	if !strings.Contains(out, "event=panic") {
		t.Errorf("no panic event: %q", out)
	}
}

func TestCounters(t *testing.T) {
	var buf bytes.Buffer
	SetOutput(&buf)
	defer SetOutput(os.Stderr)
	RegisterOK.Inc()
	LogCounters()
	if !strings.Contains(buf.String(), "register_ok=") || !strings.Contains(buf.String(), " panics=") {
		t.Errorf("%q", buf.String())
	}
}
