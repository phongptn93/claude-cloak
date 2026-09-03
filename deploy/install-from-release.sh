#!/usr/bin/env bash
# Install Claude Cloak straight from a published GitHub Release.
#
#   curl -fsSL https://raw.githubusercontent.com/phongptn93/claude-cloak/main/deploy/install-from-release.sh | sudo bash
#   sudo ./install-from-release.sh v0.2.0          # pin a version
#   sudo BASE_URL=http://10.0.0.5/rel ./install-from-release.sh v0.2.0   # internal mirror
#
# No clone, no build, no toolchain: the host downloads a bundle, checks it
# against the published SHA256SUMS, and installs the wheel with pinned
# hashes. Re-run it to upgrade; settings and counters are left alone.
set -euo pipefail

REPO="${REPO:-phongptn93/claude-cloak}"
VERSION="${1:-latest}"
BASE_URL="${BASE_URL:-}"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }
command -v tar  >/dev/null || { echo "tar is required" >&2; exit 1; }

if [ -z "$BASE_URL" ]; then
    if [ "$VERSION" = "latest" ]; then
        BASE_URL="https://github.com/$REPO/releases/latest/download"
    else
        BASE_URL="https://github.com/$REPO/releases/download/$VERSION"
    fi
fi

echo "Fetching $VERSION from $BASE_URL"
curl -fsSL "$BASE_URL/SHA256SUMS" -o "$WORK/SHA256SUMS"

# The checksum file names the artifact, so the exact version never has to be
# guessed from the tag — a "latest" install still lands on a known filename.
BUNDLE=$(awk '{print $2}' "$WORK/SHA256SUMS" | grep -E '^claude-cloak-.*\.tar\.gz$' | head -1)
[ -n "$BUNDLE" ] || { echo "SHA256SUMS names no bundle" >&2; exit 1; }

curl -fsSL "$BASE_URL/$BUNDLE" -o "$WORK/$BUNDLE"

echo "Verifying checksum"
( cd "$WORK" && sha256sum -c --ignore-missing --status SHA256SUMS ) \
    || { echo "checksum mismatch — refusing to install $BUNDLE" >&2; exit 1; }

# Optional but worth it when the host has gh: proves the bundle came out of
# the repository's own release workflow rather than someone's laptop.
if command -v gh >/dev/null 2>&1 && [ -n "${GH_TOKEN:-${GITHUB_TOKEN:-}}" ]; then
    echo "Verifying build provenance"
    gh attestation verify "$WORK/$BUNDLE" --repo "$REPO" \
        || { echo "provenance verification failed" >&2; exit 1; }
else
    echo "Skipping provenance check (needs gh + GH_TOKEN)"
fi

tar -xzf "$WORK/$BUNDLE" -C "$WORK"
DIR=$(find "$WORK" -mindepth 1 -maxdepth 1 -type d -name 'claude-cloak-*' | head -1)
exec "$DIR/deploy/systemd/install.sh"
