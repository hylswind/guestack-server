# Verifying an image

> How to check that the PCR values a login page trusts came from this repository's source code.

The login page accepts a backend only if its attestation document reports the PCR values pinned in the page. This procedure ties those values to a commit of this repository, so you can read the code that handles phone numbers.

You need the month's `measurements.json`, the login page's `EPOCH_ID` and `PCRS`, a clone of this repository, the [GitHub CLI](https://cli.github.com/), and `jq`.

## Steps

### 1. Verify the attestation

```sh
gh attestation verify measurements.json \
  --repo hylswind/guestack-server \
  --signer-workflow hylswind/guestack-server/.github/workflows/build-image.yml \
  --source-ref refs/heads/main \
  --deny-self-hosted-runners \
  --format json > attestation.json
```

This must succeed. It proves that this exact file was produced by this repository's build workflow, from the `main` branch, on a GitHub-hosted runner.

### 2. Read the commit from the attestation

```sh
commit=$(jq -r '.[0].verificationResult.signature.certificate.sourceRepositoryDigest' attestation.json)
echo "$commit"
```

This is the commit the image was built from. `measurements.json` does not repeat it, because only the signed attestation can vouch for it.

### 3. Check the month

```sh
git show "$commit:.github/workflows/build-image.yml" | grep 'EPOCH_ID:'
```

The value must equal `EPOCH_ID` in the login page. The workflow compiles it into `guestackd`, so it is part of the measured image.

### 4. Check the PCRs

```sh
jq -r '.Measurements | "PCR4  \(.PCR4)\nPCR7  \(.PCR7)\nPCR12 \(.PCR12)"' measurements.json
```

Each value must equal the same index in the login page's `PCRS`, ignoring letter case.

If all four steps pass, the backend that the login page accepts runs the code at `$commit`.

## What the PCRs cover

| PCR | Covers |
|-----|--------|
| PCR4 | The unified kernel image. It contains the dm-verity root hash, so it also covers the whole root filesystem, including `guestackd` |
| PCR7 | The Secure Boot state. The image uses standard boot, so this is the value for Secure Boot off with empty key databases |
| PCR12 | Any kernel command line passed in from outside the unified kernel image. The expected value means none was |

> [!IMPORTANT]
> This check relies on GitHub's build service and Sigstore to state truthfully what was built, and on the inputs listed in [`image/INPUTS.md`](image/INPUTS.md). The image is not reproducible, so rebuilding it is not a way to verify it.
