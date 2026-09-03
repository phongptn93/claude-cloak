#!/usr/bin/env bash
# Install or update the native systemd deployment.
#
#   sudo deploy/systemd/install.sh [git-ref]
#
# Idempotent: re-run it to deploy a new revision. It never touches
# /var/lib/claude-cloak/.env, which holds the captured identity and secrets.
set -euo pipefail

APP_DIR=/opt/claude-cloak
DATA_DIR=/var/lib/claude-cloak
SERVICE_USER=claude-cloak
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REF="${1:-}"

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }

command -v uv >/dev/null 2>&1 || {
    echo "Installing uv…"
    curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh
}

id "$SERVICE_USER" >/dev/null 2>&1 || useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 750 "$DATA_DIR"
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 750 "$DATA_DIR/acme"

if [ -n "$REF" ] && [ -d "$REPO_DIR/.git" ]; then
    git -C "$REPO_DIR" fetch --quiet origin
    git -C "$REPO_DIR" checkout --quiet "$REF"
fi

rm -rf "$APP_DIR"
install -d "$APP_DIR"
cp -r "$REPO_DIR/pyproject.toml" "$REPO_DIR/uv.lock" "$REPO_DIR/README.md" "$REPO_DIR/src" "$APP_DIR/"

# --locked refuses to resolve: the deployed set is exactly the reviewed one.
# --no-dev leaves ruff/ty/pytest out of the production venv.
UV_COMPILE_BYTECODE=1 uv sync --project "$APP_DIR" --locked --no-dev --no-editable
chown -R root:root "$APP_DIR"

if [ ! -f "$DATA_DIR/.env" ]; then
    cp "$REPO_DIR/client/.env.example" "$DATA_DIR/.env"
    echo "Created $DATA_DIR/.env from the template — edit it before starting."
fi
chown "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR/.env"
chmod 600 "$DATA_DIR/.env"

install -m 644 "$REPO_DIR/deploy/systemd/claude-cloak.service" /etc/systemd/system/claude-cloak.service
systemctl daemon-reload
systemctl enable claude-cloak

echo
echo "Installed. Next:"
echo "  1. edit $DATA_DIR/.env  (ALLOWED_IPS, ADMIN_TOKEN, SESSION_SECRET, TLS_*)"
echo "  2. issue a certificate — see deploy/README.md"
echo "  3. systemctl restart claude-cloak && systemctl status claude-cloak"
