// Package kmssigner signs identity tokens with the operator's AWS KMS key.
// The operator is trusted not to forge identity tokens with it; the operator
// is not trusted with phone numbers.
//
// The backend has no runtime configuration. The key is a fixed alias,
// resolved in the instance's own account and region, so no key ARN or account
// ID appears in the source. The region and the instance-role
// credentials come from the instance metadata service. The SDK is built
// explicitly rather than with config.LoadDefaultConfig, which would read
// environment variables and ~/.aws files.
package kmssigner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"slices"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// KeyAlias is the issuer key. Which key it points to is the operator's
// choice.
const KeyAlias = "alias/guestack-issuer"

// imdsEndpoint is set explicitly; left empty, the IMDS client would read it
// from AWS_EC2_METADATA_SERVICE_ENDPOINT.
const imdsEndpoint = "http://169.254.169.254"

// ErrKMS is the only error of this package. It carries no detail.
var ErrKMS = errors.New("kmssigner: KMS unavailable or key unsuitable")

const callTimeout = 10 * time.Second

// API is the subset of the KMS client used here.
type API interface {
	Sign(ctx context.Context, in *kms.SignInput, opts ...func(*kms.Options)) (*kms.SignOutput, error)
	GetPublicKey(ctx context.Context, in *kms.GetPublicKeyInput, opts ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
}

// NewClient builds a KMS client for the instance's region with its
// instance-role credentials, both from IMDSv2.
func NewClient(ctx context.Context) (API, error) {
	md := imds.New(imds.Options{Endpoint: imdsEndpoint, ClientEnableState: imds.ClientEnabled})
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	out, err := md.GetRegion(ctx, &imds.GetRegionInput{})
	if err != nil || out.Region == "" {
		return nil, ErrKMS
	}
	creds := ec2rolecreds.New(func(o *ec2rolecreds.Options) { o.Client = md })
	return kms.NewFromConfig(aws.Config{
		Region:      out.Region,
		Credentials: aws.NewCredentialsCache(creds),
	}), nil
}

// Signer signs SHA-256 digests with one KMS key.
type Signer struct {
	api   API
	keyID string
}

// New checks that keyID is an ECC_NIST_P256 SIGN_VERIFY key that allows
// ECDSA_SHA_256, and returns the signer and the key's public half.
func New(ctx context.Context, api API, keyID string) (*Signer, *ecdsa.PublicKey, error) {
	if keyID == "" {
		return nil, nil, ErrKMS
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	out, err := api.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(keyID)})
	if err != nil || out.KeySpec != types.KeySpecEccNistP256 || out.KeyUsage != types.KeyUsageTypeSignVerify ||
		!slices.Contains(out.SigningAlgorithms, types.SigningAlgorithmSpecEcdsaSha256) {
		return nil, nil, ErrKMS
	}
	pub, err := x509.ParsePKIXPublicKey(out.PublicKey)
	if err != nil {
		return nil, nil, ErrKMS
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, nil, ErrKMS
	}
	return &Signer{api: api, keyID: keyID}, ec, nil
}

// SignDigest implements issuer.Signer. KMS returns a DER signature.
func (s *Signer) SignDigest(ctx context.Context, digest [32]byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	out, err := s.api.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(s.keyID),
		Message:          digest[:],
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256,
	})
	if err != nil || len(out.Signature) == 0 {
		return nil, ErrKMS
	}
	return out.Signature, nil
}
