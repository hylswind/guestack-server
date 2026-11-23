// Package channel implements the attested secure channel's message
// protection (spec/channel.md): HPKE base mode with DHKEM(P-256,
// HKDF-SHA256), HKDF-SHA256, AES-256-GCM, framed like Oblivious HTTP
// (RFC 9458 §4.3, §4.4) with Guestack's own labels.
//
// The server side is KeyPair.OpenRequest + Response.Seal. The client side
// (SealRequest + Pending.OpenResponse) exists for tests and the dev client;
// the login page implements the same construction in JavaScript.
package channel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
)

const (
	// Label is the HPKE info prefix of a request.
	Label = "guestack/channel/v1"
	// ResponseLabel is the exporter context of the response secret.
	ResponseLabel = "guestack/channel/v1 response"

	keyID  = 0x01
	kemID  = 0x0010 // DHKEM(P-256, HKDF-SHA256)
	kdfID  = 0x0001 // HKDF-SHA256
	aeadID = 0x0002 // AES-256-GCM

	headerLen = 7
	encLen    = 65 // uncompressed P-256 point
	tagLen    = 16
	nk        = 32 // AES-256 key length
	nn        = 12 // AES-GCM nonce length
	// ResponseNonceLen is max(Nn, Nk).
	ResponseNonceLen = 32
)

// ErrChannel is the only error of this package. It carries no detail.
var ErrChannel = errors.New("channel: cannot open or seal message")

// Header is hdr = key_id(1) ‖ kem_id(2) ‖ kdf_id(2) ‖ aead_id(2).
func Header() []byte {
	return []byte{keyID, kemID >> 8, kemID & 0xff, kdfID >> 8, kdfID & 0xff, aeadID >> 8, aeadID & 0xff}
}

// Info is the HPKE info: Label ‖ 0x00 ‖ hdr.
func Info() []byte {
	return append(append([]byte(Label), 0), Header()...)
}

func kem() hpke.KEM { return hpke.DHKEM(ecdh.P256()) }

// KeyPair is the backend's channel key, generated at process start and kept
// only in memory.
type KeyPair struct {
	priv hpke.PrivateKey
}

// Generate creates a fresh channel key pair.
func Generate() (*KeyPair, error) {
	priv, err := kem().GenerateKey()
	if err != nil {
		return nil, ErrChannel
	}
	return &KeyPair{priv: priv}, nil
}

// newKeyPairFromBytes is used by the vectors only.
func newKeyPairFromBytes(sk []byte) (*KeyPair, error) {
	priv, err := kem().NewPrivateKey(sk)
	if err != nil {
		return nil, ErrChannel
	}
	return &KeyPair{priv: priv}, nil
}

// PublicKey returns the 65-byte uncompressed public key (SerializePublicKey).
func (k *KeyPair) PublicKey() []byte { return k.priv.PublicKey().Bytes() }

func (k *KeyPair) String() string   { return "channel.KeyPair" }
func (k *KeyPair) GoString() string { return "channel.KeyPair" }

// Response holds what is needed to seal the answer to one request.
type Response struct {
	enc    []byte
	secret []byte
}

// OpenRequest decrypts enc_request = hdr ‖ enc ‖ ct.
func (k *KeyPair) OpenRequest(msg []byte) ([]byte, *Response, error) {
	if len(msg) < headerLen+encLen+tagLen || string(msg[:headerLen]) != string(Header()) {
		return nil, nil, ErrChannel
	}
	enc := msg[headerLen : headerLen+encLen]
	ct := msg[headerLen+encLen:]
	r, err := hpke.NewRecipient(enc, k.priv, hpke.HKDFSHA256(), hpke.AES256GCM(), Info())
	if err != nil {
		return nil, nil, ErrChannel
	}
	pt, err := r.Open(nil, ct)
	if err != nil {
		return nil, nil, ErrChannel
	}
	secret, err := r.Export(ResponseLabel, ResponseNonceLen)
	if err != nil {
		return nil, nil, ErrChannel
	}
	return pt, &Response{enc: append([]byte(nil), enc...), secret: secret}, nil
}

// Seal encrypts the response: response_nonce ‖ ct.
func (r *Response) Seal(pt []byte) ([]byte, error) {
	nonce := make([]byte, ResponseNonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, ErrChannel
	}
	return sealResponse(r.enc, r.secret, nonce, pt)
}

// responseAEAD derives the response key and nonce:
// prk = Extract(salt = enc ‖ response_nonce, ikm = secret),
// key = Expand(prk, "key", Nk), nonce = Expand(prk, "nonce", Nn).
func responseAEAD(enc, secret, responseNonce []byte) (cipher.AEAD, []byte, error) {
	salt := append(append([]byte(nil), enc...), responseNonce...)
	prk, err := hkdf.Extract(sha256.New, secret, salt)
	if err != nil {
		return nil, nil, ErrChannel
	}
	key, err := hkdf.Expand(sha256.New, prk, "key", nk)
	if err != nil {
		return nil, nil, ErrChannel
	}
	nonce, err := hkdf.Expand(sha256.New, prk, "nonce", nn)
	if err != nil {
		return nil, nil, ErrChannel
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, ErrChannel
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, ErrChannel
	}
	return aead, nonce, nil
}

func sealResponse(enc, secret, responseNonce, pt []byte) ([]byte, error) {
	aead, nonce, err := responseAEAD(enc, secret, responseNonce)
	if err != nil {
		return nil, err
	}
	return aead.Seal(append([]byte(nil), responseNonce...), nonce, pt, nil), nil
}

// Pending is the client's state between sending a request and reading its response.
type Pending struct {
	enc    []byte
	secret []byte
}

// SealRequest encrypts a request to the channel public key (client side).
func SealRequest(publicKey, pt []byte) ([]byte, *Pending, error) {
	pk, err := kem().NewPublicKey(publicKey)
	if err != nil {
		return nil, nil, ErrChannel
	}
	enc, s, err := hpke.NewSender(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), Info())
	if err != nil {
		return nil, nil, ErrChannel
	}
	ct, err := s.Seal(nil, pt)
	if err != nil {
		return nil, nil, ErrChannel
	}
	secret, err := s.Export(ResponseLabel, ResponseNonceLen)
	if err != nil {
		return nil, nil, ErrChannel
	}
	msg := append(append(Header(), enc...), ct...)
	return msg, &Pending{enc: enc, secret: secret}, nil
}

// OpenResponse decrypts response_nonce ‖ ct (client side).
func (p *Pending) OpenResponse(msg []byte) ([]byte, error) {
	if len(msg) < ResponseNonceLen+tagLen {
		return nil, ErrChannel
	}
	aead, nonce, err := responseAEAD(p.enc, p.secret, msg[:ResponseNonceLen])
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, nonce, msg[ResponseNonceLen:], nil)
	if err != nil {
		return nil, ErrChannel
	}
	return pt, nil
}
