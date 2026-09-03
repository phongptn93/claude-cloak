#!/usr/bin/env bash
# Install or update the native systemd deployment.
#
#   sudo deploy/systemd/install.sh
#
# Two modes, chosen automatically:
#   release bundle — a wheel and a hash-pinned requirements.txt sit next to
#                    this script's parent. Nothing is built or resolved, and
#                    uv is not required: the host's own python3 (>=3.11) and
#                    pip install exactly the reviewed artifact. uv is used
#                    when already present, purely because it is faster.
#   source tree    — a git checkout with pyproject.toml and uv.lock. Needs
#                    uv, and installs it if missing. Still no resolution:
#                    `uv sync --locked`.
#
# Idempotent: re-run to deploy a new revision. Never touches
# /var/lib/claude-cloak/.env, which holds the captured identity and secrets.
set -euo pipefail

APP_DIR=/opt/claude-cloak
DATA_DIR=/var/lib/claude-cloak
SERVICE_USER=claude-cloak
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }

export PATH="/usr/local/bin:$PATH"

id "$SERVICE_USER" >/dev/null 2>&1 \
    || useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 750 "$DATA_DIR"
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 755 "$DATA_DIR/acme"
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 700 "$DATA_DIR/tls"

WHEEL=$(ls "$ROOT"/claude_cloak-*.whl 2>/dev/null | head -1 || true)

rm -rf "$APP_DIR"
install -d "$APP_DIR"

if [ -n "$WHEEL" ] && [ -f "$ROOT/requirements.txt" ]; then
    echo "Installing release bundle $(cat "$ROOT/VERSION" 2>/dev/null || basename "$WHEEL")"

    PY=$(command -v python3.13 || command -v python3.12 || command -v python3.11 || command -v python3)
    "$PY" - <<'CHECK' || { echo "python >= 3.11 required, found $("$PY" -V)" >&2; exit 1; }
import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)
CHECK

    # --require-hashes refuses any artifact whose hash is not the one the
    # bundle was built against. uv only makes this faster; the fallback is
    # the interpreter's own venv + pip, so a host needs no extra tooling.
    if command -v uv >/dev/null 2>&1; then
        uv venv --python "$PY" "$APP_DIR/.venv" >/dev/null
        UV_COMPILE_BYTECODE=1 uv pip install --python "$APP_DIR/.venv/bin/python" \
            --require-hashes -r "$ROOT/requirements.txt" --quiet
        UV_COMPILE_BYTECODE=1 uv pip install --python "$APP_DIR/.venv/bin/python" \
            --no-deps "$WHEEL" --quiet
    else
        "$PY" -m venv "$APP_DIR/.venv"
        "$APP_DIR/.venv/bin/pip" install --quiet --upgrade pip
        "$APP_DIR/.venv/bin/pip" install --quiet --require-hashes -r "$ROOT/requirements.txt"
        "$APP_DIR/.venv/bin/pip" install --quiet --no-deps "$WHEEL"
        "$APP_DIR/.venv/bin/python" -m compileall -q "$APP_DIR/.venv" >/dev/null 2>&1 || true
    fi
    cp "$ROOT/VERSION" "$APP_DIR/VERSION" 2>/dev/null || true
    cp "$ROOT/GIT_SHA" "$APP_DIR/GIT_SHA" 2>/dev/null || true
    ENV_TEMPLATE="$ROOT/.env.example"
elif [ -f "$ROOT/pyproject.toml" ] && [ -f "$ROOT/uv.lock" ]; then
    echo "Installing from source tree (no release bundle found)"
    command -v uv >/dev/null 2>&1 || {
        echo "Installing uv (needed to build from source)…"
        curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh
    }
    cp "$ROOT/pyproject.toml" "$ROOT/uv.lock" "$ROOT/README.md" "$APP_DIR/"
    cp -r "$ROOT/src" "$APP_DIR/"
    UV_COMPILE_BYTECODE=1 uv sync --project "$APP_DIR" --locked --no-dev --no-editable
    ENV_TEMPLATE="$ROOT/client/.env.example"
else
    echo "neither a release bundle nor a source tree found in $ROOT" >&2
    exit 1
fi

chown -R root:root "$APP_DIR"
[ -x "$APP_DIR/.venv/bin/claude-cloak" ] || { echo "entry point missing" >&2; exit 1; }

if [ ! -f "$DATA_DIR/.env" ]; then
    cp "$ENV_TEMPLATE" "$DATA_DIR/.env"
    echo "Created $DATA_DIR/.env from the template — edit it before starting."
fi
chown "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR/.env"
chmod 600 "$DATA_DIR/.env"

install -m 644 "$ROOT/deploy/systemd/claude-cloak.service" /etc/systemd/system/claude-cloak.service
install -d /etc/letsencrypt/renewal-hooks/deploy
install -m 755 "$ROOT/deploy/systemd/certbot-deploy-hook.sh" \
    /etc/letsencrypt/renewal-hooks/deploy/claude-cloak.sh 2>/dev/null || true
systemctl daemon-reload
systemctl enable claude-cloak >/dev/null

echo
echo "Installed $("$APP_DIR/.venv/bin/python" -c 'import claude_cloak,sys; print("claude-cloak")' 2>/dev/null || echo claude-cloak)"
echo "  settings : $DATA_DIR/.env"
echo "  entry    : $APP_DIR/.venv/bin/claude-cloak"
echo "  next     : edit .env, issue a certificate (deploy/README.md), then"
echo "             systemctl restart claude-cloak"
