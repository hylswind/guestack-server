//go:build dev

package secret

// NewFromBytes uses a given S. Dev build only: the privacy test fixes S so it
// can assert that S never appears in any output.
func NewFromBytes(key []byte) *Secret {
	s := new(Secret)
	if len(key) != len(s.key) {
		panic("secret: S must be 32 bytes")
	}
	copy(s.key[:], key)
	return s
}
