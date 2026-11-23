# External notes

> Facts this repository relies on, checked against primary sources.

**Checked** means read in the source on the date given. **Open** means not yet confirmed, and each open item says what it waits for.

| Topic | State |
|-------|-------|
| [Telegram login](#telegram-login) | Checked, including the blocking nonce check |
| [EC2 instance attestation (NitroTPM)](#ec2-instance-attestation-nitrotpm) | Documentation checked. Open items wait for a real instance |
| [GitHub artifact attestations](#github-artifact-attestations) | Open |
| [HPKE in Go](#hpke-in-go) | Checked |
| [No runtime configuration](#no-runtime-configuration) | Checked |
| [`encoding/json`](#encodingjson) | Accepted behaviour |

## Telegram login

**Sources:** https://core.telegram.org/bots/telegram-login and https://oauth.telegram.org/.well-known/openid-configuration, read 2026-11-20. Live checks with `curl` on 2026-11-20.

### Checked

- Issuer `https://oauth.telegram.org`. JWKS `https://oauth.telegram.org/.well-known/jwks.json`.
- `id_token_signing_alg_values_supported`: `RS256` (default), `ES256`, `EdDSA`, `ES256K`. "`EdDSA` and `ES256K` are restricted to the `openid` scope", so they reject `phone`. The backend accepts only `RS256` and `ES256`.
- JWKS on 2026-11-20 has four keys: `oidc-1` (RSA, RS256), `oidc-es256-1` (EC P-256, ES256), `oidc-eddsa-1` (OKP Ed25519), and `oidc-es256k-1` (EC secp256k1). The backend ignores the last two.
- `client_id` is the bot's numeric ID. The docs say `aud` "matches your Bot ID", and the example shows it as a string (`"123456789"`).
- `phone_number`: "User's verified phone number. Requires user consent." The example shows bare digits without `+`. Test logins with a small proof-of-concept app showed that the claim is **absent** when the user declines to share the number, and that sign-in still succeeds. Hence `phone_not_shared`.
- `claims_supported` lists `aud, preferred_username, phone_number, exp, iat, iss, name, picture, sub, ton`.
- The site origin must be registered in BotFather ("Allowed URLs"). The embedding page must not send `Cross-Origin-Opener-Policy: same-origin`; `same-origin-allow-popups` is acceptable.
- Script URL used by the proof-of-concept app: `https://oauth.telegram.org/js/telegram-login.js?6`. The docs page does not state a URL.
- **The script is served without `Access-Control-Allow-Origin`, even to a request that carries an `Origin` header** (2026-11-20). A `<script integrity=… crossorigin="anonymous">` load of it will fail. This affects how the login page loads the script, not the backend.

### Nonce

**Confirmed on 2026-11-20.** Key binding ([`registration.md`](registration.md)) depends on it.

- The docs describe `nonce` as a "random string to be included in the resulting `id_token`", but `nonce` is in neither the documented claims nor `claims_supported`.
- A real login with the proof-of-concept app showed the following:
  - RS256 token, key `oidc-1`, signature verified against the JWKS.
  - The token's `nonce` claim equals the nonce that was passed to `Telegram.Login.auth`. The proof of concept reads the claim named `nonce` and compares it in constant time with its session nonce.
  - That nonce was `secrets.token_urlsafe(32)`: 43 base64url characters, the same length and alphabet as Guestack's nonce.

### `id_token` lifetime

**30 seconds** (same login: `iat` 01:39:34 UTC, `exp` 01:40:04 UTC). The docs do not state a lifetime, and their example shows 3600. Consequences:

- The login page has at most 30 s between the popup returning and the backend checking `exp`. It should therefore fetch and verify the attestation **before** opening the popup, so that only `pop` signing, HPKE, and one request remain after login.
- The backend checks `exp` against the instance clock with no leeway ([`registration.md`](registration.md), rule 3). Clock skew between Telegram and the instance directly shortens the window.

## EC2 instance attestation (NitroTPM)

**Sources:** https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitrotpm-attestation.html and its sub-pages (`nitrotpm-attestation-document-content`, `nitrotpm-attestation-document-validate`, `attestation-get-doc`, `attestable-ami`, `create-pcr-compute`), plus https://docs.aws.amazon.com/kms/latest/developerguide/conditions-nitro-tpm.html. Read 2026-11-20.

### Checked

- The document is a CBOR COSE_Sign1 with tag 18 and protected header `{1: -35}` (ECDSA P-384), and an empty unprotected header.
- Payload: `module_id` (text), `timestamp` (uint, ms), `digest` = `"SHA384"`, `nitrotpm_pcrs` (index 0..31 → 32/48/64-byte bstr), `certificate` (DER), `cabundle` (array of DER), optional `public_key`, `user_data`, `nonce` (bstr, 0..1024 bytes).
- "An Attestation Document will always have their CA bundle in the following order": `[ROOT_CERT, INTERM_1, …, INTERM_N]`. **Root first**, and the leaf is not included.
- Validation: check the chain at the current date, with CRL checks disabled.
- Requesting a document: `nitro-tpm-attest --public-key … --user-data … --nonce …` (package `aws-nitro-tpm-tools`). For `--public-key`, "Only RSA keys are supported". **Hence the channel key is bound through `user_data`, which carries exactly the 65-byte `hpke_pk` ([`channel.md`](channel.md)). `public_key` is not used.**
- PCR4 (boot manager code) and PCR12 (UEFI boot binary command line) validate an Attestable AMI booted normally. PCR7 (Secure Boot policy) validates one booted with Secure Boot. KMS condition keys `kms:RecipientAttestation:NitroTPMPCR<n>` exist, and the docs name PCR4, PCR7, PCR12.
- Root: https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip, subject `CN=aws.nitro-enclaves, C=US, O=Amazon, OU=AWS`, 30-year lifetime. Published fingerprint `64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B`. The AWS page does not name the hash algorithm; its length fits SHA-256.
- Attestable AMI sample: `amazonlinux/kiwi-image-descriptions-examples`, path `al2023/attestable-image-example`. Its `edit_boot_install.sh` runs `nitro-tpm-pcr-compute --image <UKI.efi>` and writes `pcr_measurements.json`.

### Open

Waiting for a real instance and the image build:

- [ ] Recompute the root fingerprint from the downloaded file, and confirm it is SHA-256.
- [ ] Leaf certificate validity period. It is not documented, and it sets the backend's refresh interval for `/attestation`.
- [ ] Output format of `nitro-tpm-attest` (stdout or file, and whether the document is tagged). Whether absent optional fields are `null` or omitted. The dev build emits `null`, so the login page must accept both if real documents differ.
- [ ] How `--user-data` is passed (raw bytes, hex, or a file), and whether `user_data` arrives in the document unchanged.
- [ ] Which PCRs to pin for our image (PCR4 + PCR12 for standard boot, plus PCR7 if Secure Boot is used).

## GitHub artifact attestations

### Open

Before the release workflow is written, confirm these against current GitHub documentation:

- [ ] The attestation action and its permissions
- [ ] The provenance contents
- [ ] The verification command
- [ ] Release asset size limits

## HPKE in Go

Checked with go1.27.4 on 2026-11-20: the standard library has `crypto/hpke`. The release that added it is not confirmed. A source file name (`aead_fips140v1.26.go`) suggests Go 1.26, and that question is irrelevant because the toolchain is pinned.

It provides `DHKEM(ecdh.P256())`, `HKDFSHA256()`, `AES256GCM()`, `NewSender`/`NewRecipient`, `Seal`/`Open`, and `Export` on both contexts. The backend uses it and needs no third-party HPKE library. `go.mod` pins `toolchain go1.27.4`.

`spec/vectors/channel.json` has been decrypted, and its responses recomputed, by a separate hand-written RFC 9180 key schedule (Python `cryptography` for ECDH and AES-GCM, `hmac` for HKDF).

## No runtime configuration

`guestackd` reads no environment variable and no configuration file. Every setting is compiled in, so it is part of the measured image. What would otherwise be configuration is compiled in:

| Setting | Value |
|---------|-------|
| Listen address | `:8080` (`cmd/guestackd/wire_prod.go`) |
| Issuer key | KMS alias `alias/guestack-issuer`, resolved in the instance's own account and region (`internal/issuer/kmssigner`) |
| AWS region | Not compiled in. Read once at startup from IMDSv2 (`http://169.254.169.254`) |
| KMS credentials | The instance role's credentials, from the same IMDSv2 endpoint, refreshed when they expire. On EC2 there is no other way to obtain them |

> [!NOTE]
> The operator controls what IMDS returns, so its answers are untrusted input, used for these two things only. False credentials can only affect signing, and the operator already controls the issuer key. They give no access to phone numbers or to `S`.

`TestProductionReadsNoEnvironment` checks that no code of this module that the production build compiles calls `os.Getenv`, `os.LookupEnv`, `os.Environ`, `os.ExpandEnv`, `syscall.Getenv` or `syscall.Environ`.

The AWS SDK is constructed explicitly, without `config.LoadDefaultConfig`, because that function reads `AWS_*` variables and `~/.aws` files. The IMDS client's endpoint and enable state are set explicitly; left unset, it reads them from `AWS_EC2_METADATA_SERVICE_ENDPOINT` and `AWS_EC2_METADATA_DISABLED`.

### Reads this repository cannot remove

Checked 2026-11-20 against the versions in `go.mod`:

- **Go runtime and standard library:** `GODEBUG`, `GOTRACEBACK`, `GOMAXPROCS`, `GOMEMLIMIT` (runtime), `TZ` (time), `SSL_CERT_FILE` and `SSL_CERT_DIR` (crypto/x509), and `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` (the default HTTP transport, which the JWKS client and the SDK use).
- **AWS SDK:** `AWS_EXECUTION_ENV` (User-Agent), Lambda trace variables (recursion detection), a read-timeout switch (`internal/timeouts`), and a `LookupEnv` of `AWS_ENDPOINT_URL[_KMS]` in `service/kms`. That last read has no effect without the config sources that only `LoadDefaultConfig` supplies.

None of these can be set by the operator: the image has no SSH and no cloud-init, executes nothing from outside, and its measured systemd unit fixes the service's environment.

## `encoding/json`

The backend parses all JSON with the standard library's `encoding/json`. Guestack's own formats are decoded with `DisallowUnknownFields`, so unknown members are rejected. Telegram's formats (`id_token` claims, JWKS) are decoded leniently, because Telegram may add members.

`encoding/json` matches member names case-insensitively and keeps the last of duplicate members. This is accepted. Such ambiguities only matter when two parsers can be made to read the same signed bytes differently, to someone's advantage. Here, the signed inputs from outside (the `id_token` and the JWKS) come from Telegram, and every other input is produced and signed by the user's own key, so a user can only confuse their own registration.
