# Attested secure channel

> How the login page obtains a channel key it can trust, and how requests and responses are encrypted to it.

**Status:** v1 · **Vector:** [`channel.json`](vectors/channel.json)

## Overview

| Endpoint | Purpose |
|----------|---------|
| `GET /attestation` | Attestation document and channel public key |
| `POST /rpc` | Encrypted method call |
| `GET /healthz` | Liveness check |

The backend serves fixed paths, and no path contains a month. The login page reaches the backend through its `API_BASE` constant. Any month prefix in that base belongs to the internal proxy, which strips it before forwarding.

No response carries a month either: the pinned PCRs identify the image, and the image fixes the month.

## `GET /attestation`

```json
{ "doc": "<standard base64 of the attestation document>", "hpke_pk": "<b64u of the channel public key>" }
```

- `doc` uses **standard** base64 with padding (RFC 4648 §4). Every other binary value in this protocol is b64u.
- `hpke_pk` is the 65-byte uncompressed P-256 point (`0x04 ‖ X ‖ Y`), which is HPKE's `SerializePublicKey`.
- Response headers: `Content-Type: application/json`, `Cache-Control: no-store`.

The backend refreshes `doc` before its certificate chain expires. `hpke_pk` does not change during the process lifetime.

### Attestation document

This is an EC2 NitroTPM attestation document: CBOR, a COSE_Sign1 with protected header `{1: -35}` (ECDSA P-384 with SHA-384) and an empty unprotected header. Its payload is a map with these text keys:

| Key | Type | Use |
|-----|------|-----|
| `module_id` | text | Not used |
| `timestamp` | uint, ms since Unix epoch | Not used for trust |
| `digest` | text `"SHA384"` | PCR hash algorithm |
| `nitrotpm_pcrs` | map uint → bstr (48 bytes) | Compared with the login page's pinned PCRs |
| `certificate` | bstr, DER | Leaf certificate that signs the document |
| `cabundle` | array of bstr, DER | **Root first**, then intermediates. The leaf is not included |
| `public_key` | bstr or null | **Not used** (`nitro-tpm-attest` accepts RSA keys only) |
| `user_data` | bstr | **The channel key binding: exactly the 65 bytes of `hpke_pk`** |
| `nonce` | bstr or null | Not used |

Optional fields that are absent are encoded as CBOR `null`.

The encoding, as real instances produce it:

- The COSE_Sign1 is **untagged**. A parser also accepts tag 18, which the AWS documentation describes, and rejects any other tag.
- The payload map has **indefinite length** (RFC 8949 §3.2.2). A parser accepts definite and indefinite lengths for every map and array. In the recorded real document, every other item has a definite length.
- Byte and text strings have definite length. A parser may reject indefinite-length strings.

The dev build emits documents in this same format and encoding, signed under a throwaway dev root.

> [!NOTE]
> This layout was confirmed against a real instance on 2026-11-24 ([`external-notes.md`](external-notes.md)). [`vectors/attestation.json`](vectors/attestation.json) is that document.

### Verification by the login page

Abort on the first failure.

1. **Certificate chain.** The root is `cabundle[0]`. The SHA-256 of its DER bytes must equal the login page's pinned `NITRO_ROOT_SHA256`. Walk explicitly from root to leaf (`cabundle[0]`, `cabundle[1]`, …, `certificate`). Each certificate must verify under its issuer's key and be within its validity period at the current time. Do not rely on a chain builder to decide trust.
2. **COSE signature.** Build `Sig_structure = ["Signature1", protected, h'', payload]` (`protected` and `payload` as the exact byte strings from the document) and verify it with the leaf key. The algorithm is ECDSA P-384 with SHA-384, and the signature is raw `r ‖ s` (96 bytes).
3. **PCRs.** Every PCR pinned in the login page must equal `nitrotpm_pcrs[index]`.
4. **Key binding.** `user_data` must equal the decoded `hpke_pk` byte for byte.

The verified key is kept in memory only.

## Message protection

HPKE (RFC 9180), base mode, with this suite:

| | Value | ID |
|-|-------|----|
| KEM | DHKEM(P-256, HKDF-SHA256) | `0x0010` |
| KDF | HKDF-SHA256 | `0x0001` |
| AEAD | AES-256-GCM | `0x0002` |

Encapsulation follows the Oblivious HTTP message construction (RFC 9458 §4.3, §4.4) with Guestack's own labels. No relay is involved.

### Request

```
hdr         = key_id (1 byte) = 0x01 ‖ kem_id (2) = 0x0010 ‖ kdf_id (2) = 0x0001 ‖ aead_id (2) = 0x0002
info        = "guestack/channel/v1" ‖ 0x00 ‖ hdr
enc, ctx    = SetupBaseS(pkR = hpke_pk, info)
ct          = ctx.Seal(aad = "", pt = request JSON)
enc_request = hdr ‖ enc (65 bytes) ‖ ct
```

### Response

```
secret         = ctx.Export("guestack/channel/v1 response", 32)
response_nonce = 32 random bytes
prk            = HKDF-Extract(salt = enc ‖ response_nonce, ikm = secret)
key            = HKDF-Expand(prk, "key", 32)
nonce          = HKDF-Expand(prk, "nonce", 12)
enc_response   = response_nonce ‖ AES-256-GCM-Seal(key, nonce, aad = "", pt = response JSON)
```

32 is `max(Nn, Nk)` for AES-256-GCM. There is no padding.

### `POST /rpc`

Request: `Content-Type: application/octet-stream`, body `enc_request`, at most 8192 bytes.

| Condition | Status | Body |
|-----------|--------|------|
| Well-formed `enc_request` that decrypts | `200`, `Content-Type: application/octet-stream` | `enc_response` |
| Malformed or undecryptable body | `400` | Empty |
| Body too large | `413` | Empty |
| Wrong content type | `415` | Empty |

The error statuses are outside the channel, so they carry no detail.

Inner request:

```json
{ "method": "register", "params": { … } }
```

Inner response, always encrypted:

```json
{ "ok": true, "result": { … } }
{ "ok": false, "error": "<code>" }
```

`register` is the only method today (see [`registration.md`](registration.md)). An unknown method, or an inner request that is not exactly `{method, params}`, answers `bad_request`. The envelope lets methods be added later without changing the channel.

## Other endpoints

`GET /healthz` answers `200` with body `ok`. There are no other endpoints: no debug routes, no profiling.

The backend does not set CORS headers. The internal proxy adds them for the loader origin.
