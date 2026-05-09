"""
Auto-config Claude Code to use proxy.
Thêm ANTHROPIC_BASE_URL vào ~/.claude/settings.json
"""

import json
import os
import sys

if sys.platform == "win32":
    os.system("")

CLAUDE_DIR = os.path.join(os.path.expanduser("~"), ".claude")
SETTINGS_PATH = os.path.join(CLAUDE_DIR, "settings.json")

# Read LOCAL_PORT from .env in the same directory (no dotenv dependency needed here).
_env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
_local_port = "9999"
if os.path.exists(_env_path):
    with open(_env_path, "r", encoding="utf-8") as _f:
        for _line in _f:
            _line = _line.strip()
            if _line.startswith("LOCAL_PORT=") and not _line.startswith("#"):
                _val = _line.split("=", 1)[1].strip()
                if _val.isdigit():
                    _local_port = _val
                break

PROXY_URL = f"http://127.0.0.1:{_local_port}"

G = "\033[32m"
Y = "\033[33m"
C = "\033[36m"
D = "\033[2m"
R = "\033[0m"


def setup():
    # Tao thu muc .claude neu chua co
    os.makedirs(CLAUDE_DIR, exist_ok=True)

    # Doc settings hien tai
    settings = {}
    if os.path.exists(SETTINGS_PATH):
        try:
            with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
                settings = json.load(f)
        except (json.JSONDecodeError, OSError):
            settings = {}

    # Check da config chua
    env = settings.get("env", {})
    if env.get("ANTHROPIC_BASE_URL") == PROXY_URL:
        return  # Da config roi, skip

    # Them proxy URL
    if "env" not in settings:
        settings["env"] = {}
    settings["env"]["ANTHROPIC_BASE_URL"] = PROXY_URL

    # Luu
    with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2, ensure_ascii=False)

    print(f"  {G}Claude Code configured!{R}")
    print(f"  {D}{SETTINGS_PATH}{R}")
    print(f"  {C}ANTHROPIC_BASE_URL{R} = {PROXY_URL}")
    print()


if __name__ == "__main__":
    setup()
