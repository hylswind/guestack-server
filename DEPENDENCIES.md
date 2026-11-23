# Dependencies

> Everything `guestackd` links or uses to build, and why it is there.

The Go toolchain is go1.27.4, pinned by the `toolchain` line in `go.mod`.

> [!IMPORTANT]
> Every dependency outside the standard library must be justified here before it is added.

## Linked into `guestackd` (production build)

| Module | Version | Why |
|--------|---------|-----|
| Go standard library | go1.27.4 | All cryptography (`crypto/hpke`, `crypto/ecdsa`, `crypto/rsa`, `crypto/hkdf`, `crypto/hmac`, `encoding/asn1`), HTTP, TLS |
| `github.com/aws/aws-sdk-go-v2/service/kms` | v1.63.0 | `kms:GetPublicKey` and `kms:Sign` for the issuer key. Used only by `internal/issuer/kmssigner` |
| `github.com/aws/aws-sdk-go-v2/feature/ec2/imds`, `.../credentials` (`ec2rolecreds` only) | v1.20.9, v1.21.3 | The region and the instance-role credentials from IMDSv2. Hand-writing SigV4 signing and IMDSv2 tokens would be more code to audit, not less |
| `github.com/aws/aws-sdk-go-v2`, `github.com/aws/smithy-go`, `.../internal/configsources`, `.../internal/endpoints/v2` | see `go.mod` | Required by the modules above |

The SDK is constructed explicitly, without `config.LoadDefaultConfig`. That function would read environment variables and `~/.aws` files, and the backend has no runtime configuration ([`spec/external-notes.md`](spec/external-notes.md#no-runtime-configuration), "No runtime configuration"). It would also link every credential source the SDK supports (SSO, STS, external process).

List the linked packages with:

```sh
CGO_ENABLED=0 go list -deps ./cmd/guestackd | grep -v '^[a-z/0-9]*$'
```

The dev build (`-tags dev`) links the same modules plus `internal/devkeys`, `internal/attest/devfake` and the local signer. No third-party module is added for dev.

## Used at run time, not linked

| Program | Why |
|---------|-----|
| `nitro-tpm-attest` (package `aws-nitro-tpm-tools`, from the Amazon Linux release current at build time, see [`image/INPUTS.md`](image/INPUTS.md)) | AWS's tool for requesting attestation documents. It is part of the measured image. `internal/attest/nitrotpm` runs it with an empty environment and discards its standard error. Using it avoids a third-party TPM library and a hand-written TPM protocol |

## Tools only (never linked)

| Module | Why |
|--------|-----|
| `honnef.co/go/tools` v0.8.2 (`staticcheck`), and the modules it requires (`golang.org/x/tools`, `x/mod`, `x/sync`, `x/exp/typeparams`, `BurntSushi/toml`) | Linting. Declared as a `tool` in `go.mod` and run with `go tool staticcheck`. No package of this repository imports it |
