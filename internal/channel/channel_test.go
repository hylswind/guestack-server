package channel

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/hylswind/guestack-server/internal/jose"
	"github.com/hylswind/guestack-server/internal/vectors"
)

type channelVectors struct {
	Description   string        `json:"description"`
	RecipientSK   string        `json:"recipient_sk_hex"`
	RecipientPK   string        `json:"recipient_pk_hex"`
	HPKEPK        string        `json:"hpke_pk"`
	HeaderHex     string        `json:"hdr_hex"`
	InfoHex       string        `json:"info_hex"`
	ResponseLabel string        `json:"response_export_context"`
	Cases         []channelCase `json:"cases"`
	Invalid       []invalidCase `json:"invalid_requests"`
}

type channelCase struct {
	Request          string `json:"request"`
	EncRequestHex    string `json:"enc_request_hex"`
	ExportedHex      string `json:"response_secret_hex"`
	ResponseNonceHex string `json:"response_nonce_hex"`
	AEADKeyHex       string `json:"response_key_hex"`
	AEADNonceHex     string `json:"response_aead_nonce_hex"`
	Response         string `json:"response"`
	EncResponseHex   string `json:"enc_response_hex"`
}

type invalidCase struct {
	Reason        string `json:"reason"`
	EncRequestHex string `json:"enc_request_hex"`
}

var vectorSK = func() []byte { h := sha256.Sum256([]byte("guestack vector channel key")); return h[:] }()

func TestVectors(t *testing.T) {
	kp, err := newKeyPairFromBytes(vectorSK)
	if err != nil {
		t.Fatal(err)
	}
	if vectors.Update() {
		v := channelVectors{
			Description: "Request: enc_request = hdr ‖ enc ‖ ct, HPKE base mode DHKEM(P-256,HKDF-SHA256)/HKDF-SHA256/AES-256-GCM, " +
				"info = \"guestack/channel/v1\" ‖ 0x00 ‖ hdr, empty aad. Response: secret = Export(response_export_context, 32); " +
				"prk = HKDF-Extract(salt = enc ‖ response_nonce, ikm = secret); key = Expand(prk, \"key\", 32); " +
				"aead nonce = Expand(prk, \"nonce\", 12); enc_response = response_nonce ‖ AES-256-GCM(key, nonce, response, aad empty). " +
				"enc_request was produced with a random ephemeral key: decrypt it, do not try to reproduce it. " +
				"enc_response is exact for the given response_nonce.",
			RecipientSK: hex.EncodeToString(vectorSK), RecipientPK: hex.EncodeToString(kp.PublicKey()),
			HPKEPK: jose.B64(kp.PublicKey()), HeaderHex: hex.EncodeToString(Header()), InfoHex: hex.EncodeToString(Info()),
			ResponseLabel: ResponseLabel,
		}
		reqs := []struct{ req, resp string }{
			{`{"method":"register","params":{}}`, `{"ok":false,"error":"bad_request"}`},
			{`{"method":"register","params":{"id_token":"a.b.c"}}`, `{"ok":true,"result":{"identity":"x.y.z"}}`},
		}
		for i, r := range reqs {
			msg, _, err := SealRequest(kp.PublicKey(), []byte(r.req))
			if err != nil {
				t.Fatal(err)
			}
			nonce := bytes.Repeat([]byte{byte(i + 1)}, ResponseNonceLen)
			v.Cases = append(v.Cases, caseFor(t, kp, msg, r.req, r.resp, nonce))
		}
		good := v.Cases[0].EncRequestHex
		goodBytes, _ := hex.DecodeString(good)
		flip := append([]byte(nil), goodBytes...)
		flip[len(flip)-1] ^= 1
		badKeyID := append([]byte(nil), goodBytes...)
		badKeyID[0] = 0x02
		badAEAD := append([]byte(nil), goodBytes...)
		badAEAD[6] = 0x01
		v.Invalid = []invalidCase{
			{"ciphertext tag modified", hex.EncodeToString(flip)},
			{"unknown key_id", hex.EncodeToString(badKeyID)},
			{"aead_id AES-128-GCM", hex.EncodeToString(badAEAD)},
			{"truncated before ciphertext", hex.EncodeToString(goodBytes[:headerLen+encLen])},
			{"empty", ""},
		}
		vectors.Write(t, "channel.json", v)
	}

	var v channelVectors
	vectors.Load(t, "channel.json", &v)
	if v.RecipientSK != hex.EncodeToString(vectorSK) || v.RecipientPK != hex.EncodeToString(kp.PublicKey()) ||
		v.HPKEPK != jose.B64(kp.PublicKey()) || v.HeaderHex != hex.EncodeToString(Header()) ||
		v.InfoHex != hex.EncodeToString(Info()) || v.ResponseLabel != ResponseLabel {
		t.Fatal("constants differ from implementation")
	}
	if len(v.Cases) == 0 || len(v.Invalid) == 0 {
		t.Fatal("empty vectors")
	}
	for _, c := range v.Cases {
		msg, _ := hex.DecodeString(c.EncRequestHex)
		nonce, _ := hex.DecodeString(c.ResponseNonceHex)
		got := caseFor(t, kp, msg, c.Request, c.Response, nonce)
		if got != c {
			t.Errorf("case mismatch:\n got %+v\nwant %+v", got, c)
		}
	}
	for _, c := range v.Invalid {
		msg, _ := hex.DecodeString(c.EncRequestHex)
		if _, _, err := kp.OpenRequest(msg); err == nil {
			t.Errorf("%s: accepted", c.Reason)
		}
	}
}

// caseFor opens msg, checks its plaintext, and seals resp with a fixed nonce.
func caseFor(t *testing.T, kp *KeyPair, msg []byte, req, resp string, responseNonce []byte) channelCase {
	t.Helper()
	pt, r, err := kp.OpenRequest(msg)
	if err != nil || string(pt) != req {
		t.Fatalf("open: %q %v", pt, err)
	}
	// Derive key and nonce here, independently of responseAEAD, and check
	// that sealResponse produces exactly AES-256-GCM under them.
	enc := msg[headerLen : headerLen+encLen]
	prk, _ := hkdf.Extract(sha256.New, r.secret, append(append([]byte(nil), enc...), responseNonce...))
	key, _ := hkdf.Expand(sha256.New, prk, "key", 32)
	aeadNonce, _ := hkdf.Expand(sha256.New, prk, "nonce", 12)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	want := append(append([]byte(nil), responseNonce...), gcm.Seal(nil, aeadNonce, []byte(resp), nil)...)
	sealed, err := sealResponse(r.enc, r.secret, responseNonce, []byte(resp))
	if err != nil || !bytes.Equal(sealed, want) {
		t.Fatalf("sealResponse differs from independent derivation: %v", err)
	}
	return channelCase{
		Request: req, EncRequestHex: hex.EncodeToString(msg), ExportedHex: hex.EncodeToString(r.secret),
		ResponseNonceHex: hex.EncodeToString(responseNonce), AEADKeyHex: hex.EncodeToString(key),
		AEADNonceHex: hex.EncodeToString(aeadNonce), Response: resp, EncResponseHex: hex.EncodeToString(sealed),
	}
}

func TestRoundTrip(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	msg, pending, err := SealRequest(kp.PublicKey(), []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	pt, resp, err := kp.OpenRequest(msg)
	if err != nil || string(pt) != "hello" {
		t.Fatal(err)
	}
	out, err := resp.Seal([]byte("world"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := pending.OpenResponse(out)
	if err != nil || string(got) != "world" {
		t.Fatal(err)
	}
	// A response cannot be opened by a different request's context.
	_, other, _ := SealRequest(kp.PublicKey(), []byte("hello"))
	if _, err := other.OpenResponse(out); err == nil {
		t.Error("response opened under another request")
	}
	// Another key pair cannot open the request.
	kp2, _ := Generate()
	if _, _, err := kp2.OpenRequest(msg); err == nil {
		t.Error("request opened with the wrong key")
	}
}
