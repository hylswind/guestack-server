#!/usr/bin/env bash
# Runs as root in the builder container started by image/build.sh.
set -euo pipefail

out=/out
cleanup() { chown -R "${HOST_UID:-0}:${HOST_GID:-0}" "$out" 2>/dev/null || true; }
trap cleanup EXIT
exec > >(tee "$out/kiwi.log") 2>&1

dnf -y --releasever=latest upgrade
dnf -y install \
    kiwi-cli python3-kiwi kiwi-systemdeps-core python3-poetry-core qemu-img \
    veritysetup erofs-utils aws-nitro-tpm-tools util-linux findutils rsync
# edit_boot_install.sh runs nitro-tpm-pcr-compute through sudo. This container
# is already root and has no PAM setup for sudo.
printf '#!/bin/sh\nexec "$@"\n' > /usr/local/bin/sudo
chmod +x /usr/local/bin/sudo
kiwi-ng --version
rpm -q kiwi-cli aws-nitro-tpm-tools

description=/tmp/description
rm -rf "$description"
mkdir -p "$description"
cp -r /description/appliance.kiwi /description/config.sh /description/add-gpg-key.sh \
    /description/edit_boot_install.sh /description/root "$description/"
install -D -m 0755 /guestackd "$description/root/usr/bin/guestackd"
chown -R root:root "$description/root"

target=$out/build
rm -rf "$target"
kiwi-ng --loglevel 0 system build --description "$description" --target-dir "$target"

raw=$(ls "$target"/*.raw | head -n 1)
mv "$raw" "$out/image.raw"
cp "$target/pcr_measurements.json" "$out/measurements.json"
# The packages come from the latest Amazon Linux release, so the build log is
# the record of their exact versions.
cat "$target"/*.packages
rm -rf "$target"
