"""
Auto-config Claude Code to use proxy.
Thêm ANTHROPIC_BASE_URL vào ~/.claude/settings.json

Usage:
  python setup_claude.py                  # local proxy at http://127.0.0.1:<LOCAL_PORT>
  python setup_claude.py --remote URL     # point to a shared VM, e.g. http://10.0.0.5:9999
"""

import argparse
import json
import os
import sys

if sys.platform == "win32":
    os.system("")

CLAUDE_DIR = os.path.join(os.path.expanduser("~"), ".claude")
SETTINGS_PATH = os.path.join(CLAUDE_DIR, "settings.json")


def _read_local_port() -> str:
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.exists(env_path):
        return "9999"
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("LOCAL_PORT=") and not line.startswith("#"):
                val = line.split("=", 1)[1].strip()
                if val.isdigit():
                    return val
                break
    return "9999"


G = "\033[32m"
Y = "\033[33m"
C = "\033[36m"
D = "\033[2m"
R = "\033[0m"


def setup(proxy_url: str):
    os.makedirs(CLAUDE_DIR, exist_ok=True)

    settings = {}
    if os.path.exists(SETTINGS_PATH):
        try:
            with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
                settings = json.load(f)
        except (json.JSONDecodeError, OSError):
            settings = {}

    env = settings.get("env", {})
    if env.get("ANTHROPIC_BASE_URL") == proxy_url:
        return

    if "env" not in settings:
        settings["env"] = {}
    settings["env"]["ANTHROPIC_BASE_URL"] = proxy_url

    with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2, ensure_ascii=False)

    print(f"  {G}Claude Code configured!{R}")
    print(f"  {D}{SETTINGS_PATH}{R}")
    print(f"  {C}ANTHROPIC_BASE_URL{R} = {proxy_url}")
    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Configure Claude Code to use a Claude Cloak proxy")
    parser.add_argument(
        "--remote",
        metavar="URL",
        help="Use a shared VM proxy at this URL instead of the local one (e.g. http://10.0.0.5:9999)",
    )
    args = parser.parse_args()

    if args.remote:
        url = args.remote.rstrip("/")
    else:
        url = f"http://127.0.0.1:{_read_local_port()}"

    setup(url)
