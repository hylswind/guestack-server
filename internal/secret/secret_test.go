package secret

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"testing"

	"github.com/hylswind/guestack-server/internal/vectors"
)

type guestIDVectors struct {
	Description string        `json:"description"`
	Label       string        `json:"label"`
	Cases       []guestIDCase `json:"cases"`
}

type guestIDCase struct {
	SecretHex string `json:"secret_hex"`
	Phone     string `json:"phone"`
	HMACHex   string `json:"hmac_hex"`
	B16Hex    string `json:"first16_hex"`
	UUIDHex   string `json:"after_bits_hex"`
	GuestID   string `json:"guest_id"`
}

var uuidV8 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func vectorSecrets() [][]byte {
	seq := make([]byte, 32)
	for i := range seq {
		seq[i] = byte(i)
	}
	ff := make([]byte, 32)
	for i := range ff {
		ff[i] = 0xff
	}
	h := sha256.Sum256([]byte("guestack vector secret"))
	return [][]byte{seq, ff, h[:]}
}

var vectorPhones = []string{"+447700900456", "+15550001234", "+447700900123", "+12345", "+888012345678"}

func TestVectors(t *testing.T) {
	if vectors.Update() {
		v := guestIDVectors{
			Description: "guest_id = UUIDv8 from HMAC-SHA256(S, label ‖ phone): first16 = hmac[0:16]; " +
				"after_bits = first16 with b[6] = (b[6] & 0x0f) | 0x80 and b[8] = (b[8] & 0x3f) | 0x80; " +
				"guest_id = after_bits as lowercase 8-4-4-4-12. phone is already normalised (see phone.json). " +
				"Phone policy is not applied here.",
			Label: guestIDLabel,
		}
		for _, s := range vectorSecrets() {
			for _, p := range vectorPhones {
				mac := hmac.New(sha256.New, s)
				mac.Write([]byte(guestIDLabel + p))
				sum := mac.Sum(nil)
				var b [16]byte
				copy(b[:], sum)
				first := hex.EncodeToString(b[:])
				setUUIDv8Bits(&b)
				v.Cases = append(v.Cases, guestIDCase{
					SecretHex: hex.EncodeToString(s), Phone: p, HMACHex: hex.EncodeToString(sum),
					B16Hex: first, UUIDHex: hex.EncodeToString(b[:]), GuestID: guestID(s, p),
				})
			}
		}
		vectors.Write(t, "guest-id.json", v)
	}

	var v guestIDVectors
	vectors.Load(t, "guest-id.json", &v)
	if v.Label != guestIDLabel {
		t.Fatalf("label %q", v.Label)
	}
	versionChanged, variantChanged := false, false
	for _, c := range v.Cases {
		key, _ := hex.DecodeString(c.SecretHex)
		if got := guestID(key, c.Phone); got != c.GuestID {
			t.Errorf("%s: got %s want %s", c.Phone, got, c.GuestID)
		}
		if !uuidV8.MatchString(c.GuestID) {
			t.Errorf("%s is not a lowercase v8 UUID", c.GuestID)
		}
		first, _ := hex.DecodeString(c.B16Hex)
		after, _ := hex.DecodeString(c.UUIDHex)
		if first[6] != after[6] {
			versionChanged = true
		}
		if first[8] != after[8] {
			variantChanged = true
		}
	}
	if !versionChanged || !variantChanged {
		t.Error("vectors do not exercise both bit-setting steps")
	}
}

func TestGuestIDByHand(t *testing.T) {
	// Recomputed here without guestID's helpers.
	key := make([]byte, 32)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("guestack/guest-id/v1\x00+15550001234"))
	b := mac.Sum(nil)[:16]
	b[6] = b[6]&0x0f | 0x80
	b[8] = b[8]&0x3f | 0x80
	want := fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
	if got := guestID(key, "+15550001234"); got != want {
		t.Errorf("got %s want %s", got, want)
	}
}

func TestSecretNotPrintable(t *testing.T) {
	s := New()
	for _, f := range []string{"%v", "%+v", "%#v", "%s"} {
		out := fmt.Sprintf(f, s)
		if out != "secret.Secret" {
			t.Errorf("%s printed %q", f, out)
		}
	}
	if New().GuestID("+15550001234") == s.GuestID("+15550001234") {
		t.Error("two secrets gave the same guest ID")
	}
}
