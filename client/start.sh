#!/usr/bin/env bash
# Claude Cloak — launcher for macOS / Linux
# Mirrors start.bat behaviour: creates .env, kills stale process, installs deps,
# configures Claude Code, then runs the proxy.
set -euo pipefail
cd "$(dirname "$0")"

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
