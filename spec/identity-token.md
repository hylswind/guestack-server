# Identity token

> The signed token that carries a user's guest ID and public key until the end of the month.

**Status:** v1 · **Vectors:** [`identity-token.json`](vectors/identity-token.json), [`issuer-key.json`](vectors/issuer-key.json)

> [!IMPORTANT]
> It is called the **identity token** everywhere, and `identity` as a field name. It is never called a certificate: in this system "certificate" means only the AWS X.509 certificates inside the attestation document.

## Format

A compact JWS with `ES256` (raw `r ‖ s`, 64 bytes).

Header, members in this order:

```json
{"alg":"ES256","typ":"guestack-id+jwt","kid":"<kid>"}
```

Payload, exactly these five members in this order:

```json
{"iss":"guestack","sub":"<guest_id>","exp":<epoch_end>,"boot":"<b64u of 8 bytes>","cnf":{"jwk":{"kty":"EC","crv":"P-256","x":"…","y":"…"}}}
```

| Claim | Value |
|-------|-------|
| `iss` | The fixed string `guestack`. It is an identifier, not a URL, and nothing is fetched from it |
| `sub` | The guest ID ([identifiers.md](identifiers.md)) |
| `exp` | `epoch_end` of the backend's `EPOCH_ID`, exactly |
| `boot` | b64u of 8 random bytes chosen at process start. The RP SDK returns it and takes no action on it |
| `cnf.jwk` | The user's public key from the registration request |

There is deliberately no `iat`: nothing uses it, and it would reveal when the user logged in. There is also no `epoch`, because the month follows from `exp`.

The backend serialises header and payload without whitespace, in the member order above. The vector gives the exact bytes. Verifiers must not depend on member order. They parse the JSON.

## Issuer key and `kid`

The issuer key is an AWS KMS key: `ECC_NIST_P256`, `SIGN_VERIFY`, `ECDSA_SHA_256`. The backend addresses it by the compiled-in alias `alias/guestack-issuer` in the instance's own account and region. At startup it checks the key's spec, usage and algorithm.

To sign, the backend:

1. Signs `SHA-256(signing input)` with `MessageType: DIGEST`. KMS returns an ASN.1 DER `ECDSA-Sig-Value`.
2. Converts it to raw `r ‖ s`. Each integer is left-padded to 32 bytes. Non-DER encodings, zero or negative values, and values longer than 32 bytes are rejected.
3. Verifies the converted signature against the issuer public key before returning the token.

`kid` = b64u of the RFC 7638 SHA-256 thumbprint of the issuer public key (43 characters). The backend computes it at startup from the public key it obtains with `kms:GetPublicKey`, which returns DER.

There is no issuer domain and no JWKS endpoint. The RP SDK bundles the issuer public keys. [`issuer-keys.pem`](issuer-keys.pem) in this directory is the source the SDK copies them from. It holds only the current issuer key, as one PEM `PUBLIC KEY` block exactly as downloaded from the AWS KMS console, and a new key overwrites it. The SDK derives the JWK and `kid` from the PEM, and [`issuer-key.json`](vectors/issuer-key.json) is the test vector for that derivation. Dev keys are never listed in it. Key rotation ships as an SDK release that lists both the old and the new key for a transition period.

## Verification by RPs

The RP SDK does this:

1. Find the key by `kid`.
2. Require `typ` `guestack-id+jwt` and `iss` `guestack`.
3. `sub` must be a lowercase version-8 UUID.
4. The token is valid while `now < exp + 60 s`.
