# Identifiers and keys

> The epoch, phone number, guest ID, and key types used across the protocol.

**Status:** v1 · **Vectors:** [`epoch.json`](vectors/epoch.json), [`phone.json`](vectors/phone.json), [`guest-id.json`](vectors/guest-id.json)

## Epoch

`EPOCH_ID` is a UTC year-month `YYYY-MM` (regular expression `^[0-9]{4}-(0[1-9]|1[0-2])$`, year ≥ 1970). It is the only epoch constant. It is compiled into `guestackd` at link time, so it is part of the measured image, and the login page writes it in its constants block.

- `epoch_start` is 00:00:00 UTC on the 1st of that month.
- `epoch_end` is 00:00:00 UTC on the 1st of the following month.
- An instant `t` is in the epoch when `epoch_start ≤ t < epoch_end`.

`guestackd` refuses to start when `EPOCH_ID` is missing or invalid. Nothing at run time can change it.

## Phone number

`phone` is Telegram's `phone_number` claim, normalised:

1. Remove one leading `+`, if present. Telegram sends bare digits, for example `447700900456`.
2. What remains must be 5 to 15 ASCII digits `0-9`. Nothing else is allowed: no spaces, separators, a second `+`, or non-ASCII digits.
3. `phone` = `+` followed by those digits.

An input that fails step 2 is rejected with `id_token_invalid`.

### Phone policy

This is a constant of the binary, so the operator cannot change it. A normalised `phone` that starts with one of these prefixes is rejected with `phone_not_allowed`:

| Prefix | Reason |
|--------|--------|
| `+888` | Telegram anonymous numbers |

## Guest ID

`S` is 32 bytes from `crypto/rand`, generated once at process start and held only in memory. It is never persisted, exported, logged, or sealed.

```
h  = HMAC-SHA256(key = S, message = "guestack/guest-id/v1\0" ‖ phone)
b  = h[0..16)
b[6] = (b[6] & 0x0f) | 0x80      -- UUID version 8
b[8] = (b[8] & 0x3f) | 0x80      -- RFC 9562 variant
guest_id = lowercase hex of b as 8-4-4-4-12
```

The result is 36 characters and matches:

```
^[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$
```

UUID version 8 is reserved for application-defined values. 122 bits come from the HMAC.

`phone` is UTF-8 (in fact ASCII) bytes. The label ends with one zero byte.

> [!NOTE]
> A restart creates a new `S`, so every guest ID changes. This is an accepted trade-off: `S` is never persisted, so it cannot survive a restart. The identity token's `boot` claim lets RPs notice it.

## Keys

| Key | Type | Lifetime |
|-----|------|----------|
| User key | ECDSA P-256, generated in the browser, `extractable: false` | Until its identity token expires |
| Channel key | HPKE DHKEM(P-256, HKDF-SHA256) key pair | Generated at process start, memory only |
| Issuer key | AWS KMS `ECC_NIST_P256`, `SIGN_VERIFY`, `ECDSA_SHA_256` | Stable across epochs; rotated by SDK release |
| `S` | 32 random bytes | Process lifetime, memory only |
| `boot` | 8 random bytes | Process lifetime |
