#!/usr/bin/env bash
# Builds the raw disk image with KIWI NG in a privileged Amazon Linux container.
# It runs in the build workflow, on a GitHub-hosted runner.
#
#   image/build.sh <guestackd binary> <output directory>
#
# The output directory receives image.raw and measurements.json, which is the
# unmodified output of nitro-tpm-pcr-compute.
set -euo pipefail

BUILDER=amazonlinux:2023

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <guestackd binary> <output directory>" >&2
    exit 2
fi
binary=$(realpath "$1")
out=$(realpath -m "$2")
description=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
mkdir -p "$out"

sudo modprobe loop 2>/dev/null || true
docker pull "$BUILDER"

run_build() {
    docker run --privileged --rm \
        -v /dev:/dev \
        -v "$description:/description:ro" \
        -v "$binary:/guestackd:ro" \
        -v "$out:/out" \
        -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
        "$BUILDER" bash /description/in-container.sh
}

if ! run_build; then
    # KIWI's documented container quirk: loop nodes created on the host are not
    # visible on the first attempt. One retry is enough.
    grep -qi "loop device" "$out/kiwi.log" || exit 1
    echo "loop device problem on the first attempt, retrying once" >&2
    run_build
fi

jq -e '.Measurements | [.PCR4, .PCR7, .PCR12]
       | all(type == "string" and test("^[0-9a-fA-F]{96}$"))' "$out/measurements.json" >/dev/null || {
    echo "measurements.json must hold PCR4, PCR7 and PCR12" >&2
    exit 1
}

ls -l "$out"
cat "$out/measurements.json"
