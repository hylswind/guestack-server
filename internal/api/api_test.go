package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/hylswind/guestack-server/internal/channel"
	"github.com/hylswind/guestack-server/internal/registration"
	"github.com/hylswind/guestack-server/internal/safelog"
)

type staticAtt struct{}

func (staticAtt) Body() []byte { return []byte(`{"doc":"AA==","hpke_pk":"AA"}`) }

type fakeReg struct {
	got   json.RawMessage
	panic bool
}

func (f *fakeReg) Register(_ context.Context, p json.RawMessage) (string, registration.Code) {
	if f.panic {
		panic("+15550001234 in a panic")
	}
	f.got = p
	return "x.y.z", registration.OK
}

func setup(t *testing.T, reg Registrar) (*channel.KeyPair, http.Handler) {
	t.Helper()
	keys, err := channel.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return keys, New(keys, staticAtt{}, reg).Handler()
}

func post(h http.Handler, ct string, body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/rpc", bytes.NewReader(body))
	if ct != "" {
		r.Header.Set("Content-Type", ct)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func call(t *testing.T, keys *channel.KeyPair, h http.Handler, inner string) string {
	t.Helper()
	msg, pending, err := channel.SealRequest(keys.PublicKey(), []byte(inner))
	if err != nil {
		t.Fatal(err)
	}
	w := post(h, "application/octet-stream", msg)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("status %d", w.Code)
	}
	pt, err := pending.OpenResponse(w.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return string(pt)
}

func TestRPC(t *testing.T) {
	reg := &fakeReg{}
	keys, h := setup(t, reg)
	if got := call(t, keys, h, `{"method":"register","params":{"a":1}}`); got != `{"ok":true,"result":{"identity":"x.y.z"}}` {
		t.Errorf("got %s", got)
	}
	if string(reg.got) != `{"a":1}` {
		t.Errorf("params %s", reg.got)
	}
	for _, inner := range []string{
		`{"method":"other","params":{}}`, `{"method":"register"}`, `{"method":"register","params":{},"x":1}`, `not json`,
	} {
		if got := call(t, keys, h, inner); got != `{"ok":false,"error":"bad_request"}` {
			t.Errorf("%s: got %s", inner, got)
		}
	}
}

func TestRPCOutsideChannel(t *testing.T) {
	keys, h := setup(t, &fakeReg{})
	msg, _, _ := channel.SealRequest(keys.PublicKey(), []byte(`{}`))
	for _, c := range []struct {
		name, ct string
		body     []byte
		want     int
	}{
		{"no content type", "", msg, http.StatusUnsupportedMediaType},
		{"json content type", "application/json", msg, http.StatusUnsupportedMediaType},
		{"garbage", "application/octet-stream", []byte("+15550001234"), http.StatusBadRequest},
		{"too large", "application/octet-stream", make([]byte, MaxBody+1), http.StatusRequestEntityTooLarge},
	} {
		w := post(h, c.ct, c.body)
		if w.Code != c.want || w.Body.Len() != 0 {
			t.Errorf("%s: %d %q", c.name, w.Code, w.Body.String())
		}
	}
}

func TestRoutes(t *testing.T) {
	_, h := setup(t, &fakeReg{})
	for _, c := range []struct {
		method, path string
		want         int
	}{
		{"GET", "/attestation", 200}, {"GET", "/healthz", 200}, {"GET", "/rpc", 405},
		{"POST", "/attestation", 405}, {"GET", "/debug/pprof/", 404}, {"GET", "/", 404},
		{"GET", "/2026-12/attestation", 404},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(c.method, c.path, nil))
		if w.Code != c.want {
			t.Errorf("%s %s: %d", c.method, c.path, w.Code)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/attestation", nil))
	if w.Header().Get("Access-Control-Allow-Origin") != "" || w.Header().Get("Cache-Control") != "no-store" {
		t.Error("unexpected headers")
	}
}

func TestPanicIsRecoveredSilently(t *testing.T) {
	var buf bytes.Buffer
	safelog.SetOutput(&buf)
	defer safelog.SetOutput(os.Stderr)
	keys, h := setup(t, &fakeReg{panic: true})
	msg, _, _ := channel.SealRequest(keys.PublicKey(), []byte(`{"method":"register","params":{}}`))
	w := post(h, "application/octet-stream", msg)
	if w.Code != http.StatusInternalServerError || w.Body.Len() != 0 {
		t.Errorf("status %d body %q", w.Code, w.Body.String())
	}
	if strings.Contains(buf.String(), "1555") || !strings.Contains(buf.String(), "event=panic") {
		t.Errorf("log %q", buf.String())
	}
}
