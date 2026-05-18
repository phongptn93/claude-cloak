#!/usr/bin/env bash
# Claude Cloak — server-mode launcher for a shared VM.
#
# Sets DEPLOY_MODE=server, refuses to start without ALLOWED_IPS, and binds
# the proxy on LOCAL_HOST (default 0.0.0.0) so whitelisted client machines
# can point their Claude Code at it via ANTHROPIC_BASE_URL=http://<vm>:9999.
#
# Run once on the VM. Each client just runs `setup_claude.py --remote URL`.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -f .env ]; then
    if [ -f .env.example ]; then
        cp .env.example .env
        echo "Created .env from .env.example — edit it before re-running."
        echo "Required: DEPLOY_MODE=server, ALLOWED_IPS=..., CAPTURED_* identity."
        exit 1
    fi
    echo ".env is missing. Aborting." >&2
    exit 1
fi

# ── Force server mode (override anything in .env) ──────────────────────────
export DEPLOY_MODE=server

# ── Read LOCAL_PORT from .env ──────────────────────────────────────────────
LOCAL_PORT=$(grep -E '^LOCAL_PORT=' .env 2>/dev/null | cut -d= -f2 | tr -d '[:space:]')
LOCAL_PORT=${LOCAL_PORT:-9999}

# ── Sanity check: ALLOWED_IPS must be non-empty in .env ────────────────────
ALLOWED=$(grep -E '^ALLOWED_IPS=' .env 2>/dev/null | cut -d= -f2- | tr -d '[:space:]')
if [ -z "$ALLOWED" ]; then
    echo
    echo "  ERROR: ALLOWED_IPS is empty in .env."
    echo "  Set ALLOWED_IPS=<comma-separated IPs/CIDRs> before starting server mode."
    echo "  Example: ALLOWED_IPS=203.0.113.5,198.51.100.0/24"
    echo
    exit 1
fi

# ── Sanity check: CAPTURED_USER_AGENT must be present ──────────────────────
if ! grep -E '^CAPTURED_USER_AGENT=.+' .env >/dev/null 2>&1; then
    echo
    echo "  WARNING: no CAPTURED_USER_AGENT in .env."
    echo "  Run the proxy in local mode on one machine first to capture identity,"
    echo "  then copy the CAPTURED_* lines into this VM's .env."
    echo
fi

# ── Kill any stale process on the port ────────────────────────────────────
if command -v lsof &>/dev/null; then
    PIDS=$(lsof -ti ":$LOCAL_PORT" 2>/dev/null || true)
    if [ -n "$PIDS" ]; then
        echo "Killing stale process on port $LOCAL_PORT…"
        echo "$PIDS" | xargs kill -9 2>/dev/null || true
    fi
elif command -v fuser &>/dev/null; then
    fuser -k "${LOCAL_PORT}/tcp" 2>/dev/null || true
fi

# ── Auto-install dependencies if missing ──────────────────────────────────
if ! python3 -c "import httpx" 2>/dev/null; then
    echo "Installing dependencies…"
    python3 -m pip install -r requirements.txt
fi

# Server mode never auto-configures local Claude Code — skip setup_claude.py.
echo "Starting Claude Cloak in SERVER mode on port $LOCAL_PORT…"
echo "Whitelisted: $ALLOWED"
echo
python3 proxy.py
