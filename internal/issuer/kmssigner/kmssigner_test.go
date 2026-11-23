package kmssigner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/hylswind/guestack-server/internal/issuer"
	"github.com/hylswind/guestack-server/internal/jose"
)

// fakeKMS behaves like KMS for one key: DER signatures over a digest.
type fakeKMS struct {
	priv    *ecdsa.PrivateKey
	spec    types.KeySpec
	usage   types.KeyUsageType
	signErr error
	lastIn  *kms.SignInput
}

func (f *fakeKMS) GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	der, _ := x509.MarshalPKIXPublicKey(&f.priv.PublicKey)
	return &kms.GetPublicKeyOutput{
		PublicKey: der, KeySpec: f.spec, KeyUsage: f.usage,
		SigningAlgorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha256},
	}, nil
}

func (f *fakeKMS) Sign(_ context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	f.lastIn = in
	if f.signErr != nil {
		return nil, f.signErr
	}
	sig, err := ecdsa.SignASN1(rand.Reader, f.priv, in.Message)
	return &kms.SignOutput{Signature: sig}, err
}

func newFake(t *testing.T) *fakeKMS {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeKMS{priv: priv, spec: types.KeySpecEccNistP256, usage: types.KeyUsageTypeSignVerify}
}

func TestIssueThroughKMS(t *testing.T) {
	f := newFake(t)
	s, pub, err := New(context.Background(), f, "alias/test")
	if err != nil {
		t.Fatal(err)
	}
	iss, err := issuer.New(s, pub)
	if err != nil {
		t.Fatal(err)
	}
	user, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cnf, _ := jose.NewP256JWK(&user.PublicKey)
	tok, err := iss.Issue(context.Background(), issuer.Claims{Sub: "x", Exp: 1, Boot: "AAAAAAAAAAA", Cnf: cnf})
	if err != nil || tok == "" {
		t.Fatal(err)
	}
	if f.lastIn.MessageType != types.MessageTypeDigest || f.lastIn.SigningAlgorithm != types.SigningAlgorithmSpecEcdsaSha256 ||
		len(f.lastIn.Message) != 32 || *f.lastIn.KeyId != "alias/test" {
		t.Errorf("unexpected Sign input %+v", f.lastIn)
	}
}

func TestRejectsUnsuitableKeys(t *testing.T) {
	for name, mutate := range map[string]func(*fakeKMS){
		"wrong spec":  func(f *fakeKMS) { f.spec = types.KeySpecEccNistP384 },
		"wrong usage": func(f *fakeKMS) { f.usage = types.KeyUsageTypeEncryptDecrypt },
	} {
		f := newFake(t)
		mutate(f)
		if _, _, err := New(context.Background(), f, "k"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, _, err := New(context.Background(), newFake(t), ""); err == nil {
		t.Error("empty key ID accepted")
	}
}

func TestSignError(t *testing.T) {
	f := newFake(t)
	s, _, _ := New(context.Background(), f, "k")
	f.signErr = errors.New("throttled")
	if _, err := s.SignDigest(context.Background(), [32]byte{}); err != ErrKMS {
		t.Error(err)
	}
}
