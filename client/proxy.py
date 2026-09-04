"""Backward-compatible entry point.

The proxy now lives in the ``claude_cloak`` package (``src/claude_cloak``).
This shim keeps ``python proxy.py`` — and every launcher, service definition
and shortcut that points at it — working. Prefer ``uv run claude-cloak``.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from claude_cloak.cli import main  # noqa: E402

if __name__ == "__main__":
    main()
