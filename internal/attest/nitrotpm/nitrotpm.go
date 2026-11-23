// Package nitrotpm will request attestation documents from the instance's
// NitroTPM. It is not implemented yet and fails closed: a production binary
// cannot start without real attestation.
package nitrotpm

import (
	"context"
	"errors"
)

// ErrNotImplemented is returned until NitroTPM attestation is implemented.
var ErrNotImplemented = errors.New("nitrotpm: not implemented")

// Provider is the production attestation provider.
type Provider struct{}

// New returns the provider. It always fails for now.
func New() (*Provider, error) { return nil, ErrNotImplemented }

// Document implements attest.Provider.
func (*Provider) Document(context.Context, []byte) ([]byte, error) {
	return nil, ErrNotImplemented
}
