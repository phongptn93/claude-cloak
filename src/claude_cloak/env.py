"""`.env` discovery, loading, and in-place key updates.

The proxy used to live at ``client/proxy.py`` and anchored ``.env`` to its own
directory. The package now lives elsewhere, so the file is resolved in this
order — existing installs keep using the very same ``client/.env``:

1. ``$CLAUDE_CLOAK_ENV`` (explicit override, wins always)
2. ``./.env`` relative to the current working directory — every launcher
   script ``cd``s into ``client/`` before starting the proxy
3. ``<repo>/client/.env`` next to the installed source tree
4. ``./.env`` (created on demand) when none of the above exist
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from dotenv import load_dotenv

ENV_FILENAME = ".env"
ENV_PATH_VAR = "CLAUDE_CLOAK_ENV"


def _candidate_paths() -> list[Path]:
    candidates = [Path.cwd() / ENV_FILENAME]
    # <site-packages|src>/claude_cloak/env.py -> repo root -> client/.env
    repo_root = Path(__file__).resolve().parents[2]
    candidates.append(repo_root / "client" / ENV_FILENAME)
    candidates.append(repo_root / ENV_FILENAME)
    return candidates


def resolve_env_path() -> Path:
    override = os.getenv(ENV_PATH_VAR, "").strip()
    if override:
        return Path(override).expanduser().resolve()
    for candidate in _candidate_paths():
        if candidate.is_file():
            return candidate.resolve()
    return (Path.cwd() / ENV_FILENAME).resolve()


ENV_PATH: str = str(resolve_env_path())

load_dotenv(ENV_PATH)


def data_path(filename: str, override: str = "") -> str:
    """Resolve a sibling data file (``.quota.json``, ``.coach.json``)."""
    if override.strip():
        return override.strip()
    return str(Path(ENV_PATH).parent / filename)


def env_key(header: str) -> str:
    """Header name -> ``CAPTURED_`` env key (``x-app`` -> ``CAPTURED_X_APP``)."""
    return "CAPTURED_" + header.upper().replace("-", "_")


def save_to_env(key: str, value: str) -> None:
    """Create/replace ``key`` in the ``.env`` file, preserving everything else."""
    path = Path(ENV_PATH)
    if not path.exists():
        path.write_text(f"{key}={value}\n", encoding="utf-8")
        return

    content = path.read_text(encoding="utf-8")
    pattern = rf"^{re.escape(key)}=.*$"
    if re.search(pattern, content, re.MULTILINE):
        content = re.sub(pattern, f"{key}={value}", content, flags=re.MULTILINE)
    else:
        if content and not content.endswith("\n"):
            content += "\n"
        content += f"{key}={value}\n"
    path.write_text(content, encoding="utf-8")


def env_str(key: str, default: str = "") -> str:
    return os.getenv(key, default).strip()


def env_int(key: str, default: int) -> int:
    """Unparseable or empty falls back to the default instead of crashing at
    import time, which is what the original ``int(os.getenv(...))`` calls did."""
    try:
        return int(os.getenv(key, str(default)).strip())
    except (TypeError, ValueError):
        return default


def env_float(key: str, default: float) -> float:
    try:
        return float(os.getenv(key, str(default)).strip())
    except (TypeError, ValueError):
        return default


def env_bool(key: str, default: bool) -> bool:
    """``true`` (any case) is the only truthy spelling.

    An empty value is False, not the default — ``TIMING_JITTER=`` in a .env
    means off, exactly as it did before the settings were centralised.
    """
    raw = os.getenv(key)
    if raw is None:
        return default
    return raw.strip().lower() == "true"


def env_list(key: str, default: tuple[str, ...] = ()) -> list[str]:
    raw = os.getenv(key, "")
    if not raw.strip():
        return list(default)
    return [item.strip() for item in raw.split(",") if item.strip()]
