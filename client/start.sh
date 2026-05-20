#!/usr/bin/env bash
# Claude Cloak — LOCAL mode launcher for macOS / Linux.
#
# Runs a single-machine proxy at 127.0.0.1:9999 and auto-configures Claude
# Code to use it. For a shared VM deployment use start-server.sh instead,
# and on the clients use setup-remote.sh (no local proxy needed).
set -euo pipefail
cd "$(dirname "$0")"

echo "============================================================"
echo "  Claude Cloak — LOCAL MODE"
echo "  Runs a per-device proxy on 127.0.0.1:9999."
echo "  For a shared VM:"
echo "    - on the VM:     ./start-server.sh"
echo "    - on each user:  ./setup-remote.sh http://VM:9999 <username>"
echo "============================================================"
echo

# Force local mode for this process so a leftover DEPLOY_MODE=server in
# .env can't accidentally bind 0.0.0.0 from start.sh.
export DEPLOY_MODE=local

# ── Create .env if absent ──────────────────────────────────────────────────────
if [ ! -f .env ]; then
    if [ -f .env.example ]; then
        cp .env.example .env
        echo "Created .env from .env.example"
    else
        printf 'LOCAL_PORT=9999\n' > .env
    fi
fi

# ── Read LOCAL_PORT ────────────────────────────────────────────────────────────
LOCAL_PORT=$(grep -E '^LOCAL_PORT=' .env 2>/dev/null | cut -d= -f2 | tr -d '[:space:]')
LOCAL_PORT=${LOCAL_PORT:-9999}

# ── Kill any existing process on the port ─────────────────────────────────────
if command -v lsof &>/dev/null; then
    PIDS=$(lsof -ti ":$LOCAL_PORT" 2>/dev/null || true)
    if [ -n "$PIDS" ]; then
        echo "Killing stale process on port $LOCAL_PORT…"
        echo "$PIDS" | xargs kill -9 2>/dev/null || true
    fi
elif command -v fuser &>/dev/null; then
    fuser -k "${LOCAL_PORT}/tcp" 2>/dev/null || true
fi

# ── Auto-install dependencies if missing ─────────────────────────────────────
if ! python3 -c "import httpx" 2>/dev/null; then
    echo "Installing dependencies…"
    python3 -m pip install -r requirements.txt
fi

# ── Configure Claude Code ─────────────────────────────────────────────────────
python3 setup_claude.py

# ── Launch proxy ──────────────────────────────────────────────────────────────
python3 proxy.py
