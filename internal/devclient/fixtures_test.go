//go:build dev

package devclient

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/hylswind/guestack-server/internal/devkeys"
	"github.com/hylswind/guestack-server/internal/issuer"
	"github.com/hylswind/guestack-server/internal/jose"
	"github.com/hylswind/guestack-server/internal/vectors"
)

type devFixtures struct {
	Description      string            `json:"description"`
	NitroRootPEM     string            `json:"nitro_root_pem"`
	NitroRootSHA256  string            `json:"nitro_root_sha256_hex"`
	PinnedPCRs       map[string]string `json:"pinned_pcrs_hex"`
	AllPCRs          map[string]string `json:"all_pcrs_hex"`
	TelegramClientID int64             `json:"telegram_client_id"`
	TelegramIssuer   string            `json:"telegram_issuer"`
	TelegramKeys     []devTGKey        `json:"telegram_keys"`
	IssuerJWK        map[string]string `json:"issuer_jwk"`
	IssuerKid        string            `json:"issuer_kid"`
	IssuerKeyPEM     string            `json:"issuer_private_key_pem"`
}

type devTGKey struct {
	Kid           string `json:"kid"`
	Alg           string `json:"alg"`
	PrivateKeyPEM string `json:"private_key_pem"`
}

func pemFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "devkeys", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func buildFixtures(t *testing.T) devFixtures {
	root, _ := devkeys.NitroRoot()
	sum := sha256.Sum256(root.Raw)
	pins := DevPins()
	all := devkeys.PCRs()
	f := devFixtures{
		Description: "Dev build fixtures (NOT production values). A dev guestackd (make run-dev) attests under this root " +
			"with these PCRs, accepts id_tokens signed by these Telegram keys with aud = telegram_client_id, and signs " +
			"identity tokens with this issuer key. Tests of the login page put nitro_root_sha256_hex and pinned_pcrs_hex in a " +
			"temporary copy of its constants block; RP SDK tests bundle issuer_jwk. Every private key here is public.",
		NitroRootPEM:     string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})),
		NitroRootSHA256:  hex.EncodeToString(sum[:]),
		PinnedPCRs:       map[string]string{},
		AllPCRs:          map[string]string{},
		TelegramClientID: devkeys.TelegramClientID,
		TelegramIssuer:   "https://oauth.telegram.org",
		TelegramKeys: []devTGKey{
			{devkeys.TelegramRS256Kid, "RS256", pemFile(t, "telegram-rs256.key.pem")},
			{devkeys.TelegramES256Kid, "ES256", pemFile(t, "telegram-es256.key.pem")},
		},
		IssuerKeyPEM: pemFile(t, "issuer.key.pem"),
	}
	for i, v := range pins.PCRs {
		f.PinnedPCRs[itoa(i)] = hex.EncodeToString(v)
	}
	for i, v := range all {
		f.AllPCRs[itoa(i)] = hex.EncodeToString(v)
	}
	k, _ := jose.NewP256JWK(&devkeys.Issuer().PublicKey)
	pt, _ := k.PublicKey().Bytes()
	f.IssuerJWK = map[string]string{"kty": "EC", "crv": "P-256", "x": jose.B64(pt[1:33]), "y": jose.B64(pt[33:])}
	f.IssuerKid = issuer.KeyID(k)
	return f
}

func itoa(i int) string { return string(rune('0'+i/10)) + string(rune('0'+i%10)) }

func TestDevFixturesVectors(t *testing.T) {
	want := buildFixtures(t)
	if vectors.Update() {
		vectors.Write(t, "dev-build.json", want)
	}
	var got devFixtures
	vectors.Load(t, "dev-build.json", &got)
	if got.NitroRootSHA256 != want.NitroRootSHA256 || got.IssuerKid != want.IssuerKid ||
		got.TelegramClientID != want.TelegramClientID || len(got.PinnedPCRs) != 3 || len(got.AllPCRs) != 24 {
		t.Fatal("spec/vectors/dev-build.json is out of date: make vectors")
	}
	for k, v := range want.AllPCRs {
		if got.AllPCRs[k] != v {
			t.Fatal("PCRs out of date")
		}
	}
	// The PEM in the file is the certificate the dev backend uses.
	b, _ := pem.Decode([]byte(got.NitroRootPEM))
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil || sha256.Sum256(c.Raw) != DevPins().RootSHA256 {
		t.Error("root PEM mismatch")
	}
}
