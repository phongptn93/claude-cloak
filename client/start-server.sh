#!/usr/bin/env bash
# Claude Cloak — server-mode launcher for a shared VM (macOS / Linux).
#
# Interactive setup the first time it runs: prompts for ALLOWED_IPS and
# (optionally) IP_LABELS, per-user spend caps, identity-lock IP, stats
# privacy. On subsequent runs it just boots — re-run the wizard with
#   ./start-server.sh --reconfigure
# to change any of those.
#
# After the first /v1/messages request from a whitelisted device, the proxy
# auto-captures that device's identity headers and locks them in .env for
# every other device.
set -euo pipefail
cd "$(dirname "$0")/.."

FORCE_WIZARD=0
case "${1:-}" in
    --reconfigure|--reconfig|-r) FORCE_WIZARD=1 ;;
esac

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

# ── First-run wizard (also runs with --reconfigure) ────────────────────────
if [ -z "$ALLOWED_IPS" ] || [ "$FORCE_WIZARD" = "1" ]; then
    # Pull current values so reconfigure shows them as defaults.
    cur_allowed="$(read_env ALLOWED_IPS)"
    cur_labels="$(read_env IP_LABELS)"
    cur_uq="$(read_env USER_QUOTA_ENABLED)"
    cur_period="$(read_env USER_QUOTA_PERIOD)"
    cur_default="$(read_env USER_QUOTA_DEFAULT_USD)"
    cur_caps="$(read_env USER_QUOTA_CAPS)"
    cur_capture_ip="$(read_env CAPTURE_LOCK_FROM_IP)"
    cur_stats_private="$(read_env STATS_PRIVATE)"

    prompt_with_default() {
        # prompt_with_default "label" "default" → echoes user value (default if empty)
        local label="$1" def="$2" ans=""
        if [ -n "$def" ]; then
            read -rp "${label} [${def}]: " ans
            echo "${ans:-$def}"
        else
            read -rp "${label}: " ans
            echo "$ans"
        fi
    }

    echo
    echo "============================================================"
    echo "  Claude Cloak — Server Mode Setup"
    if [ "$FORCE_WIZARD" = "1" ]; then
        echo "  (reconfigure — current values shown as defaults)"
    fi
    echo "============================================================"
    echo "Press Enter to keep the shown default."
    echo

    ALLOWED_IPS="$(prompt_with_default 'Allowed IPs / CIDRs (e.g. 203.0.113.5,10.0.0.0/24)' "$cur_allowed")"
    if [ -z "$ALLOWED_IPS" ]; then
        echo
        echo "  ERROR: ALLOWED_IPS cannot be empty in server mode."
        echo
        exit 1
    fi

    IP_LABELS="$(prompt_with_default 'IP labels (optional, e.g. 203.0.113.5:phong)' "$cur_labels")"

    USER_QUOTA_ENABLED=false
    USER_QUOTA_PERIOD=monthly
    USER_QUOTA_DEFAULT_USD=0
    USER_QUOTA_CAPS=
    uq_default="N"
    [ "$cur_uq" = "true" ] && uq_default="Y"
    read -rp "Enable per-user spend cap? (y/N) [${uq_default}]: " enable_uq
    enable_uq="${enable_uq:-$uq_default}"
    if [[ "$enable_uq" =~ ^[Yy]$ ]]; then
        USER_QUOTA_ENABLED=true
        USER_QUOTA_PERIOD="$(prompt_with_default '  Period (monthly/daily)' "${cur_period:-monthly}")"
        USER_QUOTA_DEFAULT_USD="$(prompt_with_default '  Default cap USD per user' "${cur_default:-20.0}")"
        USER_QUOTA_CAPS="$(prompt_with_default '  Per-label overrides (e.g. phong:50,huy:30)' "$cur_caps")"
    fi

    echo
    echo "── Hardening (optional) ───────────────────────────────────"
    CAPTURE_LOCK_FROM_IP="$(prompt_with_default 'Restrict identity capture to one IP (prevents wrong device locking the fingerprint)' "$cur_capture_ip")"

    sp_default="N"
    [ "$cur_stats_private" = "true" ] && sp_default="Y"
    read -rp "Make dashboard/quota private to admin (loopback only)? (y/N) [${sp_default}]: " enable_sp
    enable_sp="${enable_sp:-$sp_default}"
    STATS_PRIVATE=false
    [[ "$enable_sp" =~ ^[Yy]$ ]] && STATS_PRIVATE=true

    echo
    echo "Writing config to .env…"
    upsert_env DEPLOY_MODE server
    upsert_env ALLOWED_IPS "$ALLOWED_IPS"
    upsert_env IP_LABELS "$IP_LABELS"
    upsert_env USER_QUOTA_ENABLED "$USER_QUOTA_ENABLED"
    upsert_env USER_QUOTA_PERIOD "$USER_QUOTA_PERIOD"
    upsert_env USER_QUOTA_DEFAULT_USD "$USER_QUOTA_DEFAULT_USD"
    upsert_env USER_QUOTA_CAPS "$USER_QUOTA_CAPS"
    upsert_env CAPTURE_LOCK_FROM_IP "$CAPTURE_LOCK_FROM_IP"
    upsert_env STATS_PRIVATE "$STATS_PRIVATE"
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
# ── Ensure uv is available ────────────────────────────────────────────────────
if ! command -v uv &>/dev/null; then
    echo "uv not found — installing (https://astral.sh/uv)…"
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:$PATH"
fi
if ! command -v uv &>/dev/null; then
    echo "uv install failed. Install it manually: https://docs.astral.sh/uv/getting-started/installation/" >&2
    exit 1
fi
uv sync --quiet

echo "Starting Claude Cloak in SERVER mode on port $LOCAL_PORT…"
echo "Whitelisted: $ALLOWED_IPS"
echo
echo "The first request from a whitelisted device will auto-capture its"
echo "identity headers and lock them in .env for all other devices."
echo
uv run claude-cloak
