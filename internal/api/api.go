// Package api serves GET /attestation, POST /rpc and GET /healthz
// (spec/channel.md). There are no other routes: no debug endpoints, no
// profiling, no CORS (the internal proxy adds CORS).
package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/hylswind/guestack-server/internal/channel"
	"github.com/hylswind/guestack-server/internal/jose"
	"github.com/hylswind/guestack-server/internal/registration"
	"github.com/hylswind/guestack-server/internal/safelog"
)

// MaxBody is the largest accepted POST /rpc body.
const MaxBody = 8192

const rpcTimeout = 20 * time.Second

// Registrar handles the register method.
type Registrar interface {
	Register(ctx context.Context, params json.RawMessage) (string, registration.Code)
}

// AttestationSource returns the current GET /attestation body.
type AttestationSource interface {
	Body() []byte
}

// Server holds the handlers' dependencies.
type Server struct {
	keys *channel.KeyPair
	att  AttestationSource
	reg  Registrar
}

// New returns a Server.
func New(keys *channel.KeyPair, att AttestationSource, reg Registrar) *Server {
	return &Server{keys: keys, att: att, reg: reg}
}

// Handler returns the routes, each wrapped in panic recovery.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /attestation", s.attestation)
	mux.HandleFunc("POST /rpc", s.rpc)
	mux.HandleFunc("GET /healthz", healthz)
	return recoverer(mux)
}

// recoverer turns a handler panic into the fixed safelog event and an empty
// 500. The panic value is never printed, and net/http never sees the
// panic, so it cannot log it either.
func recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				safelog.Panics.Inc()
				safelog.Log(safelog.Panic)
				w.WriteHeader(http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	io.WriteString(w, "ok")
}

func (s *Server) attestation(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(s.att.Body())
}

func (s *Server) rpc(w http.ResponseWriter, r *http.Request) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/octet-stream" {
		empty(w, http.StatusUnsupportedMediaType)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBody))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			empty(w, http.StatusRequestEntityTooLarge)
		} else {
			empty(w, http.StatusBadRequest)
		}
		return
	}
	pt, resp, err := s.keys.OpenRequest(body)
	if err != nil {
		safelog.RPCBadEnvelope.Inc()
		empty(w, http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), rpcTimeout)
	defer cancel()
	out, err := resp.Seal(s.dispatch(ctx, pt))
	if err != nil {
		empty(w, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(out)
}

// dispatch handles the inner request and returns the inner response JSON.
func (s *Server) dispatch(ctx context.Context, pt []byte) []byte {
	var req struct {
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	if jose.DecodeJSON(pt, &req) != nil || req.Method != "register" || len(req.Params) == 0 {
		return failure(registration.BadRequest)
	}
	identity, code := s.reg.Register(ctx, req.Params)
	if code != registration.OK {
		return failure(code)
	}
	b, _ := json.Marshal(struct {
		OK     bool `json:"ok"`
		Result struct {
			Identity string `json:"identity"`
		} `json:"result"`
	}{OK: true, Result: struct {
		Identity string `json:"identity"`
	}{identity}})
	return b
}

func failure(c registration.Code) []byte {
	return []byte(`{"ok":false,"error":"` + string(c) + `"}`)
}

func empty(w http.ResponseWriter, status int) {
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
}
