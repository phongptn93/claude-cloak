"""
Auto-config Claude Code to use proxy.
Thêm ANTHROPIC_BASE_URL vào ~/.claude/settings.json

Usage:
  python setup_claude.py                  # local proxy at http://127.0.0.1:<LOCAL_PORT>
  python setup_claude.py --remote URL     # point to a shared VM, e.g. http://10.0.0.5:9999
  python setup_claude.py --transparent    # Remote-Control-compatible mode:
                                          #   leaves ANTHROPIC_BASE_URL UNSET and
                                          #   trusts the local CA via NODE_EXTRA_CA_CERTS

Transparent mode keeps Claude Code's base URL as api.anthropic.com (so Remote
Control, which v2.1.196+ gates on that hostname, keeps working). Traffic is
routed to the local proxy by a hosts entry instead of by ANTHROPIC_BASE_URL.
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


def _load_settings() -> dict:
    if os.path.exists(SETTINGS_PATH):
        try:
            with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _save_settings(settings: dict):
    with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2, ensure_ascii=False)


def setup(proxy_url: str):
    os.makedirs(CLAUDE_DIR, exist_ok=True)

    settings = _load_settings()

    env = settings.get("env", {})
    if env.get("ANTHROPIC_BASE_URL") == proxy_url:
        return

    if "env" not in settings:
        settings["env"] = {}
    settings["env"]["ANTHROPIC_BASE_URL"] = proxy_url

    _save_settings(settings)

    print(f"  {G}Claude Code configured!{R}")
    print(f"  {D}{SETTINGS_PATH}{R}")
    print(f"  {C}ANTHROPIC_BASE_URL{R} = {proxy_url}")
    print()


def setup_transparent(ca_cert: str):
    """Remote-Control-compatible mode. Leaves ANTHROPIC_BASE_URL UNSET (so Claude
    Code keeps talking to api.anthropic.com and Remote Control stays enabled) and
    trusts our local CA so TLS to the proxy validates."""
    os.makedirs(CLAUDE_DIR, exist_ok=True)
    settings = _load_settings()
    env = settings.setdefault("env", {})

    # Remove any base-URL override left over from non-transparent setup — its
    # presence is exactly what disables Remote Control.
    removed = env.pop("ANTHROPIC_BASE_URL", None)
    env["NODE_EXTRA_CA_CERTS"] = ca_cert

    _save_settings(settings)

    print(f"  {G}Claude Code configured for transparent (Remote Control) mode!{R}")
    print(f"  {D}{SETTINGS_PATH}{R}")
    if removed:
        print(f"  {Y}removed{R} ANTHROPIC_BASE_URL {D}(was {removed}){R}")
    print(f"  {C}NODE_EXTRA_CA_CERTS{R} = {ca_cert}")
    print()
    print(f"  {Y}One manual step:{R} add this line to your hosts file so")
    print(f"  api.anthropic.com resolves to the local proxy:")
    print(f"      {C}127.0.0.1  api.anthropic.com{R}")
    if sys.platform == "win32":
        print(f"  {D}(hosts file: C:\\Windows\\System32\\drivers\\etc\\hosts, edit as Administrator){R}")
    else:
        print(f"  {D}(hosts file: /etc/hosts, edit with sudo){R}")
    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Configure Claude Code to use a Claude Cloak proxy")
    parser.add_argument(
        "--remote",
        metavar="URL",
        help="Use a shared VM proxy at this URL instead of the local one (e.g. http://10.0.0.5:9999)",
    )
    parser.add_argument(
        "--transparent",
        action="store_true",
        help="Remote-Control-compatible mode: leave ANTHROPIC_BASE_URL unset and "
             "trust the local CA (certs/ca.crt) via NODE_EXTRA_CA_CERTS",
    )
    parser.add_argument(
        "--ca-cert",
        metavar="PATH",
        default=None,
        help="CA cert to trust in transparent mode (default: ./certs/ca.crt)",
    )
    args = parser.parse_args()

    if args.transparent:
        ca = args.ca_cert or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "certs", "ca.crt"
        )
        if not os.path.isfile(ca):
            print(f"  {Y}CA cert not found:{R} {ca}")
            print(f"  Generate it first:  {C}python gen_cert.py{R}")
            sys.exit(1)
        setup_transparent(os.path.abspath(ca))
    elif args.remote:
        setup(args.remote.rstrip("/"))
    else:
        setup(f"http://127.0.0.1:{_read_local_port()}")
