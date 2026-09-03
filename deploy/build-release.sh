#!/usr/bin/env bash
# Produce a self-contained release bundle: a wheel plus a hash-pinned
# requirements file, so a target host installs a reviewed artifact instead of
# building from a source tree. No git, no compiler and no dependency
# resolution happen at install time.
#
#   deploy/build-release.sh            -> dist/claude-cloak-<version>.tar.gz
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

VERSION=$(uv version --short)
STAGE="dist/stage/claude-cloak-${VERSION}"
BUNDLE="dist/claude-cloak-${VERSION}.tar.gz"

rm -rf "$STAGE" && mkdir -p "$STAGE"

# Pure-Python wheel; every runtime dependency also ships wheels, so the
# target never needs a compiler.
uv build --wheel --out-dir "$STAGE"

# Hashes come from uv.lock, so the bundle pins exactly what was reviewed and
# `pip install --require-hashes` refuses anything substituted in transit.
uv export --no-dev --no-emit-project --format requirements-txt \
    --output-file "$STAGE/requirements.txt" --quiet

cp -r deploy "$STAGE/deploy"
rm -f "$STAGE/deploy/build-release.sh"
cp client/.env.example "$STAGE/.env.example"
cp README.md "$STAGE/README.md"
printf '%s\n' "$VERSION" > "$STAGE/VERSION"
git rev-parse HEAD > "$STAGE/GIT_SHA" 2>/dev/null || true

mkdir -p dist
tar -czf "$BUNDLE" -C dist/stage "claude-cloak-${VERSION}"
rm -rf dist/stage

echo
echo "Built $BUNDLE"
tar -tzf "$BUNDLE" | sed 's/^/  /' | head -20
echo
echo "Install on a host:"
echo "  tar xzf $(basename "$BUNDLE") && cd claude-cloak-${VERSION}"
echo "  sudo deploy/systemd/install.sh"
