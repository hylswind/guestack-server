package issuer

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/hylswind/guestack-server/internal/jose"
	"github.com/hylswind/guestack-server/internal/vectors"
)

type issuerKeyVector struct {
	Description string            `json:"description"`
	PEM         string            `json:"pem"`
	JWK         map[string]string `json:"jwk"`
	Kid         string            `json:"kid"`
}

func TestIssuerKeyVectors(t *testing.T) {
	if vectors.Update() {
		priv := vectors.FixedP256(t, "guestack vector issuer key pem")
		der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		k, err := jose.NewP256JWK(&priv.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		var jwk map[string]string
		if err := json.Unmarshal(k.Canonical(), &jwk); err != nil {
			t.Fatal(err)
		}
		vectors.Write(t, "issuer-key.json", issuerKeyVector{
			Description: "Issuer key derivation: a PEM SubjectPublicKeyInfo, and the JWK and kid derived from it. " +
				"kid = b64u of the RFC 7638 SHA-256 thumbprint. Test key only: its private key is derived from a " +
				"public label, so it must never be trusted.",
			PEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
			JWK: jwk,
			Kid: KeyID(k),
		})
	}

	var v issuerKeyVector
	vectors.Load(t, "issuer-key.json", &v)

	block, rest := pem.Decode([]byte(v.PEM))
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("pem is not a single PUBLIC KEY block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("key type %T", parsed)
	}
	k, err := jose.NewP256JWK(pub)
	if err != nil {
		t.Fatal(err)
	}

	rawJWK, err := json.Marshal(v.JWK)
	if err != nil {
		t.Fatal(err)
	}
	want, err := jose.ParseP256JWK(rawJWK)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k.Canonical(), want.Canonical()) {
		t.Errorf("jwk = %s, want %s", k.Canonical(), want.Canonical())
	}
	if got := KeyID(k); got != v.Kid {
		t.Errorf("kid = %s, want %s", got, v.Kid)
	}
}
