"""Backward-compatible entry point for ``claude_cloak.tray_app``.

Prefer ``uv run --extra tray claude-cloak-tray``.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from claude_cloak.tray_app import main  # noqa: E402

if __name__ == "__main__":
    main()
