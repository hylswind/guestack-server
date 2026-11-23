// Package phone normalises Telegram's phone_number claim and applies the
// compile-time phone policy (spec/identifiers.md).
//
// The policy is a constant of the binary, so it is measured; nothing at run
// time can change it.
package phone

import "errors"

// Fixed errors. They never contain the number.
var (
	ErrMalformed  = errors.New("phone: malformed")
	ErrNotAllowed = errors.New("phone: not allowed")
)

// rejectedPrefixes are normalised prefixes that registration refuses.
// "+888" is Telegram's anonymous (Fragment) numbers.
var rejectedPrefixes = [...]string{"+888"}

// Normalize turns Telegram's phone_number into "+" followed by digits.
// Accepted input: an optional single leading "+", then 5 to 15 ASCII digits.
func Normalize(raw string) (string, error) {
	digits := raw
	if len(digits) > 0 && digits[0] == '+' {
		digits = digits[1:]
	}
	if len(digits) < 5 || len(digits) > 15 {
		return "", ErrMalformed
	}
	for i := 0; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return "", ErrMalformed
		}
	}
	return "+" + digits, nil
}

// Check returns ErrNotAllowed if a normalised number matches a rejected prefix.
func Check(normalized string) error {
	for _, p := range rejectedPrefixes {
		if len(normalized) >= len(p) && normalized[:len(p)] == p {
			return ErrNotAllowed
		}
	}
	return nil
}
