package phone

import (
	"testing"

	"github.com/hylswind/guestack-server/internal/vectors"
)

type phoneVectors struct {
	Description      string      `json:"description"`
	RejectedPrefixes []string    `json:"rejected_prefixes"`
	Cases            []phoneCase `json:"cases"`
}

type phoneCase struct {
	PhoneNumber string `json:"phone_number"`
	Phone       string `json:"phone,omitempty"`
	Error       string `json:"error,omitempty"`
}

var inputs = []string{
	"447700900456", "+447700900456", "15550001234", "12345", "123456789012345",
	"888012345678", "+888012345678", "88812345", "8880", // too short: malformed, not policy
	"", "+", "1234", "1234567890123456", "++15550001234", "+1 555 000 1234",
	"+1-555-0001234", "１５５５０００１２３４", "1555000123a", " 15550001234", "15550001234\n",
}

// result maps an input to its expected registration outcome.
func result(in string) phoneCase {
	n, err := Normalize(in)
	if err != nil {
		return phoneCase{PhoneNumber: in, Error: "id_token_invalid"}
	}
	if Check(n) != nil {
		return phoneCase{PhoneNumber: in, Phone: n, Error: "phone_not_allowed"}
	}
	return phoneCase{PhoneNumber: in, Phone: n}
}

func TestVectors(t *testing.T) {
	if vectors.Update() {
		v := phoneVectors{
			Description: "Normalisation of Telegram's phone_number claim and the compile-time phone policy. " +
				"phone: normalised value used for the guest ID. error: the registration error code.",
			RejectedPrefixes: rejectedPrefixes[:],
		}
		for _, in := range inputs {
			v.Cases = append(v.Cases, result(in))
		}
		vectors.Write(t, "phone.json", v)
	}
	var v phoneVectors
	vectors.Load(t, "phone.json", &v)
	if len(v.RejectedPrefixes) != len(rejectedPrefixes) {
		t.Fatal("rejected prefixes differ")
	}
	for i, p := range v.RejectedPrefixes {
		if p != rejectedPrefixes[i] {
			t.Fatal("rejected prefixes differ")
		}
	}
	for _, c := range v.Cases {
		if got := result(c.PhoneNumber); got != c {
			t.Errorf("%q: got %+v want %+v", c.PhoneNumber, got, c)
		}
	}
}

func TestByHand(t *testing.T) {
	if n, err := Normalize("447700900456"); err != nil || n != "+447700900456" {
		t.Error(n, err)
	}
	if n, _ := Normalize("+888012345678"); Check(n) != ErrNotAllowed {
		t.Error("+888 accepted")
	}
	if _, err := Normalize("+1 555"); err != ErrMalformed {
		t.Error("space accepted")
	}
}
