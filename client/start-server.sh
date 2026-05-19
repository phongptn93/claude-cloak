#!/usr/bin/env bash
# Claude Cloak — server-mode launcher for a shared VM (macOS / Linux).
#
# Interactive setup the first time it runs: prompts for ALLOWED_IPS and
# (optionally) IP_LABELS + per-user spend caps, then writes .env and boots
# the proxy. On subsequent runs it just boots — re-runs the wizard only
# when ALLOWED_IPS is missing.
#
# After the first /v1/messages request from a whitelisted device, the proxy
# auto-captures that device's identity headers and locks them in .env for
# every other device.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -f .env ]; then
    if [ -f .env.example ]; then
        cp .env.example .env
        echo "Created .env from .env.example"
    else
        printf 'LOCAL_PORT=9999\nDEPLOY_MODE=server\n' > .env
    fi
fi

# Force server mode for this process (overrides whatever's in .env).
export DEPLOY_MODE=server

# ── Helpers ───────────────────────────────────────────────────────────────
read_env() {
    # read_env KEY → value (empty if not set)
    grep -E "^$1=" .env 2>/dev/null | tail -1 | cut -d= -f2- | tr -d '\r'
}

upsert_env() {
    # upsert_env KEY VALUE — replace if present, else append.
    local key="$1" val="$2" tmp
    if grep -qE "^${key}=" .env 2>/dev/null; then
        tmp=$(mktemp)
        awk -v k="$key" -v v="$val" -F= '
            BEGIN { done=0 }
            $1==k && !done { print k "=" v; done=1; next }
            { print }
        ' .env > "$tmp"
        mv "$tmp" .env
    else
        printf '%s=%s\n' "$key" "$val" >> .env
    fi
}

LOCAL_PORT="$(read_env LOCAL_PORT)"
LOCAL_PORT="${LOCAL_PORT:-9999}"
ALLOWED_IPS="$(read_env ALLOWED_IPS)"

# ── First-run wizard ──────────────────────────────────────────────────────
if [ -z "$ALLOWED_IPS" ]; then
    echo
    echo "============================================================"
    echo "  Claude Cloak — Server Mode Setup"
    echo "============================================================"
    echo "This VM will accept Claude Code traffic only from the IPs you"
    echo "whitelist below. Press Enter to skip optional sections."
    echo

    read -rp "Allowed IPs / CIDRs (comma-separated, e.g. 203.0.113.5,10.0.0.0/24): " ALLOWED_IPS
    if [ -z "$ALLOWED_IPS" ]; then
        echo
        echo "  ERROR: ALLOWED_IPS cannot be empty in server mode."
        echo "  Re-run ./start-server.sh and provide at least one IP / CIDR."
        echo
        exit 1
    fi

    read -rp "IP labels (optional, e.g. 203.0.113.5:phong,10.0.0.7:huy): " IP_LABELS

    USER_QUOTA_ENABLED=false
    USER_QUOTA_PERIOD=monthly
    USER_QUOTA_DEFAULT_USD=0
    USER_QUOTA_CAPS=
    read -rp "Enable per-user spend cap? (y/N): " enable_uq
    if [[ "$enable_uq" =~ ^[Yy]$ ]]; then
        USER_QUOTA_ENABLED=true
        read -rp "  Period (monthly/daily) [monthly]: " USER_QUOTA_PERIOD
        USER_QUOTA_PERIOD="${USER_QUOTA_PERIOD:-monthly}"
        read -rp "  Default cap USD per user [20.0]: " USER_QUOTA_DEFAULT_USD
        USER_QUOTA_DEFAULT_USD="${USER_QUOTA_DEFAULT_USD:-20.0}"
        read -rp "  Per-label overrides (optional, e.g. phong:50,huy:30): " USER_QUOTA_CAPS
    fi

    echo
    echo "Writing config to .env…"
    upsert_env DEPLOY_MODE server
    upsert_env ALLOWED_IPS "$ALLOWED_IPS"
    upsert_env IP_LABELS "$IP_LABELS"
    upsert_env USER_QUOTA_ENABLED "$USER_QUOTA_ENABLED"
    upsert_env USER_QUOTA_PERIOD "$USER_QUOTA_PERIOD"
    upsert_env USER_QUOTA_DEFAULT_USD "$USER_QUOTA_DEFAULT_USD"
    upsert_env USER_QUOTA_CAPS "$USER_QUOTA_CAPS"
    echo "Done."
    echo
fi

# ── Kill stale process on the port ────────────────────────────────────────
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

echo "Starting Claude Cloak in SERVER mode on port $LOCAL_PORT…"
echo "Whitelisted: $ALLOWED_IPS"
echo
echo "The first request from a whitelisted device will auto-capture its"
echo "identity headers and lock them in .env for all other devices."
echo
python3 proxy.py
