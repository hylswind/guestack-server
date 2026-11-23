// Package registration implements the "register" method
// (spec/registration.md). Rules are applied in the spec's order; the first
// failure decides the error code.
package registration

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/hylswind/guestack-server/internal/binding"
	"github.com/hylswind/guestack-server/internal/epoch"
	"github.com/hylswind/guestack-server/internal/issuer"
	"github.com/hylswind/guestack-server/internal/jose"
	"github.com/hylswind/guestack-server/internal/phone"
	"github.com/hylswind/guestack-server/internal/safelog"
	"github.com/hylswind/guestack-server/internal/secret"
	"github.com/hylswind/guestack-server/internal/telegram"
)

// Code is a registration error code. The set is closed.
type Code string

const (
	OK               Code = ""
	BadRequest       Code = "bad_request"
	IDTokenInvalid   Code = "id_token_invalid"
	KeyBindingFailed Code = "key_binding_failed"
	PopInvalid       Code = "pop_invalid"
	PhoneNotShared   Code = "phone_not_shared"
	PhoneNotAllowed  Code = "phone_not_allowed"
	EpochNotActive   Code = "epoch_not_active"
	Internal         Code = "internal"
)

// TokenVerifier verifies Telegram id_tokens.
type TokenVerifier interface {
	Verify(ctx context.Context, token string) (*telegram.Claims, error)
}

// Service registers users.
type Service struct {
	tg     TokenVerifier
	secret *secret.Secret
	issuer *issuer.Issuer
	window epoch.Window
	boot   string
}

// New returns a Service. boot is b64u of the 8 random bytes chosen at start.
func New(tg TokenVerifier, s *secret.Secret, iss *issuer.Issuer, w epoch.Window, boot string) *Service {
	return &Service{tg: tg, secret: s, issuer: iss, window: w, boot: boot}
}

// Register handles params of a register request. It returns the identity
// token, or a code. It never returns input data in any form.
func (s *Service) Register(ctx context.Context, params json.RawMessage) (string, Code) {
	identity, code := s.register(ctx, params)
	count(code)
	return identity, code
}

func (s *Service) register(ctx context.Context, params json.RawMessage) (string, Code) {
	// Rule 1: {id_token, jwk, pop}, each present and of the right type, and
	// nothing else.
	var p struct {
		IDToken string          `json:"id_token"`
		JWK     json.RawMessage `json:"jwk"`
		Pop     string          `json:"pop"`
	}
	if jose.DecodeJSON(params, &p) != nil || p.IDToken == "" || p.Pop == "" || len(p.JWK) == 0 || p.JWK[0] != '{' {
		return "", BadRequest
	}
	idToken, pop := p.IDToken, p.Pop

	// Rules 2–3: the id_token.
	claims, err := s.tg.Verify(ctx, idToken)
	switch {
	case errors.Is(err, telegram.ErrUnavailable):
		return "", Internal
	case err != nil:
		return "", IDTokenInvalid
	}

	// Rule 4: the user key.
	jwk, err := jose.ParseP256JWK(p.JWK)
	if err != nil {
		return "", BadRequest
	}

	// Rule 5: key binding.
	if !claims.HasNonce || !binding.NonceMatches(jwk, claims.Nonce) {
		return "", KeyBindingFailed
	}

	// Rule 6: proof of possession.
	if binding.VerifyPop(pop, jwk, idToken) != nil {
		return "", PopInvalid
	}

	// Rule 7: epoch gate on the Telegram-signed iat.
	if !s.window.Contains(claims.Iat) {
		return "", EpochNotActive
	}

	// Rules 8–10: phone.
	if !claims.HasPhone {
		return "", PhoneNotShared
	}
	normalized, err := phone.Normalize(claims.PhoneNumber)
	if err != nil {
		return "", IDTokenInvalid
	}
	if phone.Check(normalized) != nil {
		return "", PhoneNotAllowed
	}

	identity, err := s.issuer.Issue(ctx, issuer.Claims{
		Sub:  s.secret.GuestID(normalized),
		Exp:  s.window.End,
		Boot: s.boot,
		Cnf:  jwk,
	})
	if err != nil {
		return "", Internal
	}
	return identity, OK
}

func count(c Code) {
	switch c {
	case OK:
		safelog.RegisterOK.Inc()
	case BadRequest:
		safelog.ErrBadRequest.Inc()
	case IDTokenInvalid:
		safelog.ErrIDToken.Inc()
	case KeyBindingFailed:
		safelog.ErrKeyBinding.Inc()
	case PopInvalid:
		safelog.ErrPop.Inc()
	case PhoneNotShared:
		safelog.ErrPhoneShared.Inc()
	case PhoneNotAllowed:
		safelog.ErrPhoneAllowed.Inc()
	case EpochNotActive:
		safelog.ErrEpoch.Inc()
	default:
		safelog.ErrInternal.Inc()
	}
}
