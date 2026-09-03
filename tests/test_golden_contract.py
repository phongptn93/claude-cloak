"""The public response contract must not drift.

`tests/golden/` was captured from the pre-refactor single-file proxy: the full
key path + value type of every JSON endpoint, and the sha256 of both HTML pages.
These files are the record that the split changed no observable output.

Deliberate additions are allowed and must be listed in ADDED_SINCE_BASELINE,
which doubles as the changelog for the public response shape. Anything else —
a renamed key, a dropped field, a changed type — fails.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import httpx
import pytest

from claude_cloak.app import create_app
from claude_cloak.web import config_html, dashboard_html

GOLDEN = Path(__file__).parent / "golden"

# Key paths added on purpose after the baseline was captured. Each entry is a
# prefix; everything under it is treated as new surface rather than drift.
ADDED_SINCE_BASELINE = {
    # TLS certificate expiry, so a renewal that stops working is visible
    # before it becomes an outage.
    "health": [".tls"],
}

ENDPOINTS = {
    "health": "/health",
    "quota": "/quota",
    "quota_users": "/quota/users",
    "coach": "/coach",
    "config_data": "/config/data",
}


def key_paths(obj, prefix=""):
    """Every leaf as ``path:type``; lists contribute their first element."""
    if isinstance(obj, dict):
        for k in sorted(obj):
            yield from key_paths(obj[k], f"{prefix}.{k}")
    elif isinstance(obj, list):
        yield f"{prefix}[]"
        if obj:
            yield from key_paths(obj[0], f"{prefix}[]")
    else:
        yield f"{prefix}:{type(obj).__name__}"


@pytest.fixture
def client():
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app()), base_url="http://testserver"
    )


@pytest.mark.parametrize(("name", "path"), sorted(ENDPOINTS.items()))
async def test_json_shape_matches_the_pre_refactor_contract(client, name, path):
    async with client:
        response = await client.get(path)
    assert response.status_code == 200

    expected = (GOLDEN / f"{name}.keys").read_text().splitlines()
    added = tuple(ADDED_SINCE_BASELINE.get(name, ()))
    actual = [k for k in key_paths(json.loads(response.text)) if not k.startswith(added)]
    assert actual == expected

    if added:
        full = list(key_paths(json.loads(response.text)))
        assert len(full) > len(actual), f"{name}: {added} is declared but absent"


@pytest.mark.parametrize(
    ("name", "render"), [("dashboard", dashboard_html), ("config", config_html)]
)
def test_html_pages_are_byte_identical(name, render):
    expected = (GOLDEN / f"{name}.html.sha256").read_text().strip()
    assert hashlib.sha256(render().encode()).hexdigest() == expected
