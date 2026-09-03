"""Backward-compatible entry point for ``claude_cloak.setup_claude``.

Prefer ``uv run claude-cloak-setup``.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from claude_cloak.setup_claude import main  # noqa: E402

if __name__ == "__main__":
    main()
