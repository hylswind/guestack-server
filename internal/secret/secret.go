// Package secret holds S, the per-process key that derives guest IDs
// (spec/identifiers.md). S is generated from crypto/rand at start, lives only
// in memory, and is never exposed: the package offers only GuestID.
package secret

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

const guestIDLabel = "guestack/guest-id/v1\x00"

// Secret holds S. Its String and GoString methods return a fixed placeholder
// so that S cannot be printed by accident.
type Secret struct {
	key [32]byte
}

// New draws S from crypto/rand.
func New() *Secret {
	s := new(Secret)
	rand.Read(s.key[:]) // never returns an error; crashes the program instead
	return s
}

// GuestID derives the guest ID of a normalised phone number ("+" then digits).
func (s *Secret) GuestID(phone string) string { return guestID(s.key[:], phone) }

func (s *Secret) String() string   { return "secret.Secret" }
func (s *Secret) GoString() string { return "secret.Secret" }

// guestID: h = HMAC-SHA256(S, label ‖ phone); b = h[0:16]; set UUID version 8
// and the RFC 9562 variant; format 8-4-4-4-12 lowercase.
func guestID(key []byte, phone string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(guestIDLabel))
	mac.Write([]byte(phone))
	var b [16]byte
	copy(b[:], mac.Sum(nil))
	setUUIDv8Bits(&b)
	return formatUUID(b)
}

func setUUIDv8Bits(b *[16]byte) {
	b[6] = (b[6] & 0x0f) | 0x80
	b[8] = (b[8] & 0x3f) | 0x80
}

func formatUUID(b [16]byte) string {
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
