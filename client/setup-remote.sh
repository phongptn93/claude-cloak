#!/usr/bin/env bash
# Claude Cloak — point Claude Code at a remote (shared VM) proxy.
#
# Asks for the VM URL + your username. Writes them as
#   ANTHROPIC_BASE_URL=http://<vm>/u/<user>
# into ~/.claude/settings.json so the VM can attribute every request to you
# on the dashboard / per-user quota.
#
# Does NOT start a local proxy — Claude Code talks to the VM directly.
#
# Usage:
#   ./setup-remote.sh                                   (prompts for both)
#   ./setup-remote.sh http://10.0.0.5:9999              (prompts for username)
#   ./setup-remote.sh http://10.0.0.5:9999 phong        (no prompts)
set -euo pipefail
cd "$(dirname "$0")"

REMOTE_URL="${1:-}"
CLOAK_USER="${2:-}"

if [ -z "$REMOTE_URL" ]; then
    read -rp "VM proxy URL (e.g. http://10.0.0.5:9999): " REMOTE_URL
fi
if [ -z "$REMOTE_URL" ]; then
    echo
    echo "  ERROR: no URL provided."
    echo
    exit 1
fi
REMOTE_URL="${REMOTE_URL%/}"

if [ -z "$CLOAK_USER" ]; then
    read -rp "Your username for the dashboard (e.g. phong) — blank to skip: " CLOAK_USER
fi

FULL_URL="$REMOTE_URL"
if [ -n "$CLOAK_USER" ]; then
    FULL_URL="$REMOTE_URL/u/$CLOAK_USER"
fi

python3 setup_claude.py --remote "$FULL_URL"

echo
if [ -n "$CLOAK_USER" ]; then
    echo "You should appear as \"$CLOAK_USER\" on the VM dashboard."
    echo "Verify any time with:"
    echo "  curl $FULL_URL/whoami"
fi
echo
