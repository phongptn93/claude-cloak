"""Test fixtures.

The package reads its configuration at import time, so every test module runs
against a throwaway ``.env`` created before ``claude_cloak`` is first imported.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

_ENV_DIR = Path(tempfile.mkdtemp(prefix="claude-cloak-tests-"))
_ENV_FILE = _ENV_DIR / ".env"
_ENV_FILE.write_text(
    "LOCAL_PORT=9999\n"
    "DEPLOY_MODE=local\n"
    "TIMING_JITTER=false\n"
    "IP_LABELS=203.0.113.5:phong,198.51.100.7:huy\n"
    "USER_QUOTA_CAPS=phong:50.0,huy:30.0\n"
    "SESSION_SECRET=testsecret\n",
    encoding="utf-8",
)
os.environ["CLAUDE_CLOAK_ENV"] = str(_ENV_FILE)


import copy  # noqa: E402

import pytest  # noqa: E402

from claude_cloak import state  # noqa: E402

_PRISTINE = {
    name: copy.deepcopy(getattr(state, name))
    for name in (
        "quota_stats",
        "stream_stats",
        "coach_stats",
        "token_saver_stats",
        "captured_identity",
        "warned_unknown_headers",
        "loki_buffer",
        "admin_failures",
    )
}
_PRISTINE_RUNTIME = copy.copy(state.runtime)


@pytest.fixture(autouse=True)
def isolated_state():
    """Give every test the process's start-up state.

    Counters live on module-level containers by design, so without this a test
    that records usage would change what the next one observes.
    """
    yield
    for name, value in _PRISTINE.items():
        container = getattr(state, name)
        container.clear()
        restored = copy.deepcopy(value)
        if isinstance(container, list):
            container.extend(restored)
        elif isinstance(container, set):
            container.update(restored)
        else:
            container.update(restored)
    for field, value in vars(_PRISTINE_RUNTIME).items():
        setattr(state.runtime, field, value)
