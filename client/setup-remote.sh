#!/usr/bin/env bash
# Claude Cloak — point Claude Code at a remote (shared VM) proxy.
#
# Usage:
#   ./setup-remote.sh                          (prompts for URL)
#   ./setup-remote.sh http://10.0.0.5:9999     (uses given URL)
#
# Writes ANTHROPIC_BASE_URL=<URL> into ~/.claude/settings.json so Claude Code
# routes through the VM. Does NOT start a local proxy.
set -euo pipefail
cd "$(dirname "$0")"

REMOTE_URL="${1:-}"
if [ -z "$REMOTE_URL" ]; then
    read -rp "Enter remote proxy URL (e.g. http://10.0.0.5:9999): " REMOTE_URL
fi

if [ -z "$REMOTE_URL" ]; then
    echo
    echo "  ERROR: no URL provided."
    echo "  Example: ./setup-remote.sh http://10.0.0.5:9999"
    echo
    exit 1
fi

python3 setup_claude.py --remote "$REMOTE_URL"
