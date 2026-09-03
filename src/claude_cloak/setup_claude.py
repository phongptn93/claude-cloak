"""Point Claude Code at a Claude Cloak proxy by editing ``~/.claude/settings.json``.

Usage:
  claude-cloak-setup                  # local proxy at http://127.0.0.1:<LOCAL_PORT>
  claude-cloak-setup --remote URL     # shared VM, e.g. http://10.0.0.5:9999
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from . import settings as cfg
from .terminal import CYAN, DIM, GREEN, RESET, enable_windows_ansi

CLAUDE_DIR = Path(os.getenv("CLAUDE_CONFIG_DIR", Path.home() / ".claude"))
SETTINGS_PATH = CLAUDE_DIR / "settings.json"
SETTINGS_ENV_KEY = "ANTHROPIC_BASE_URL"


def local_proxy_url() -> str:
    return f"http://127.0.0.1:{cfg.LOCAL_PORT}"


def setup(proxy_url: str) -> bool:
    """Write the proxy URL into Claude Code's settings. Returns True if changed."""
    CLAUDE_DIR.mkdir(parents=True, exist_ok=True)

    data: dict = {}
    if SETTINGS_PATH.exists():
        try:
            data = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            data = {}

    if data.get("env", {}).get(SETTINGS_ENV_KEY) == proxy_url:
        return False

    data.setdefault("env", {})[SETTINGS_ENV_KEY] = proxy_url
    SETTINGS_PATH.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"  {GREEN}Claude Code configured!{RESET}")
    print(f"  {DIM}{SETTINGS_PATH}{RESET}")
    print(f"  {CYAN}{SETTINGS_ENV_KEY}{RESET} = {proxy_url}")
    print()
    return True


def main() -> None:
    enable_windows_ansi()
    parser = argparse.ArgumentParser(
        description="Configure Claude Code to use a Claude Cloak proxy"
    )
    parser.add_argument(
        "--remote",
        metavar="URL",
        help="Use a shared VM proxy at this URL instead of the local one "
        "(e.g. http://10.0.0.5:9999)",
    )
    args = parser.parse_args()
    setup(args.remote.rstrip("/") if args.remote else local_proxy_url())


if __name__ == "__main__":
    main()
