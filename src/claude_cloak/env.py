"""`.env` discovery, loading, and in-place key updates.

Configuration lives at the repository root. Resolution order:

1. ``$CLAUDE_CLOAK_ENV`` (explicit override, wins always) — every packaged
   deployment sets it, so none of the steps below apply there
2. ``./.env`` relative to the current working directory
3. ``<repo>/.env`` next to the installed source tree
4. ``<repo>/client/.env`` — legacy location, used only when nothing above
   exists, and reported on stderr so it gets moved
5. ``./.env`` (created on demand) when none of the above exist
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

from dotenv import load_dotenv

ENV_FILENAME = ".env"
ENV_PATH_VAR = "CLAUDE_CLOAK_ENV"


# Older checkouts kept .env under client/. Still honoured, but last, so a
# stale copy there can never shadow the root file it was migrated to.
LEGACY_ENV_DIR = "client"


def _candidate_paths() -> list[Path]:
    # <site-packages|src>/claude_cloak/env.py -> repo root
    repo_root = Path(__file__).resolve().parents[2]
    return [
        Path.cwd() / ENV_FILENAME,
        repo_root / ENV_FILENAME,
        repo_root / LEGACY_ENV_DIR / ENV_FILENAME,
    ]


def resolve_env_path() -> Path:
    override = os.getenv(ENV_PATH_VAR, "").strip()
    if override:
        return Path(override).expanduser().resolve()
    for candidate in _candidate_paths():
        if candidate.is_file():
            if candidate.parent.name == LEGACY_ENV_DIR:
                print(
                    f"[claude-cloak] using legacy {candidate} — move it to "
                    f"{candidate.parent.parent / ENV_FILENAME}",
                    file=sys.stderr,
                )
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
