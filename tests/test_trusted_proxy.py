"""Client-IP resolution behind a reverse proxy.

Every gate in the proxy (ALLOWED_IPS, ADMIN_IPS, STATS_VIEW_IPS, user labels)
judges one address. Getting this wrong in either direction is severe: trusting
a header too readily lets anyone claim an admin IP, while not trusting it at
all collapses the whitelist to the reverse proxy's own address.
"""

from __future__ import annotations

import httpx
import pytest

from claude_cloak import settings
from claude_cloak.access import resolve_client_ip
from claude_cloak.app import create_app

TRUSTED = "10.0.0.2"
REAL_CLIENT = "203.0.113.9"


@pytest.fixture
def trusted_proxy(monkeypatch):
    monkeypatch.setattr(
        settings, "TRUSTED_PROXY_NETWORKS", settings.parse_allowed_networks(TRUSTED)
    )


def test_without_configuration_the_header_is_ignored(monkeypatch):
    monkeypatch.setattr(settings, "TRUSTED_PROXY_NETWORKS", [])
    assert resolve_client_ip(TRUSTED, REAL_CLIENT) == TRUSTED


def test_a_trusted_peer_yields_the_forwarded_client(trusted_proxy):
    assert resolve_client_ip(TRUSTED, REAL_CLIENT) == REAL_CLIENT


def test_an_untrusted_peer_cannot_forge_its_address(trusted_proxy):
    """The whole point: a direct caller claiming to be someone else is ignored."""
    assert resolve_client_ip("198.51.100.66", "127.0.0.1") == "198.51.100.66"


def test_prepended_entries_cannot_shadow_the_observed_client(trusted_proxy):
    """A client may prepend anything; only the rightmost untrusted hop counts."""
    assert resolve_client_ip(TRUSTED, f"127.0.0.1, 8.8.8.8, {REAL_CLIENT}") == REAL_CLIENT


def test_a_chain_of_trusted_hops_walks_past_them(trusted_proxy):
    assert resolve_client_ip(TRUSTED, f"{REAL_CLIENT}, {TRUSTED}") == REAL_CLIENT


def test_a_malformed_header_falls_back_to_the_peer(trusted_proxy):
    assert resolve_client_ip(TRUSTED, "not-an-ip") == TRUSTED
    assert resolve_client_ip(TRUSTED, "") == TRUSTED


async def _get(app, path, client_ip, headers=None):
    transport = httpx.ASGITransport(app=app, client=(client_ip, 12345))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        return await c.get(path, headers=headers or {})


async def test_whitelist_admits_the_forwarded_client_not_the_proxy(monkeypatch, trusted_proxy):
    monkeypatch.setattr(settings, "DEPLOY_MODE", "server")
    monkeypatch.setattr(settings, "ALLOWED_NETWORKS", settings.parse_allowed_networks(REAL_CLIENT))
    app = create_app()

    ok = await _get(app, "/health", TRUSTED, {"x-forwarded-for": REAL_CLIENT})
    assert ok.status_code == 200

    # Same proxy, a client that is not on the whitelist.
    denied = await _get(app, "/health", TRUSTED, {"x-forwarded-for": "198.51.100.66"})
    assert denied.status_code == 403


async def test_the_admin_gate_is_not_opened_by_a_forwarded_loopback(monkeypatch, trusted_proxy):
    """Regression guard for the trap this feature exists to close: a reverse
    proxy on the same host must not make every visitor an admin."""
    monkeypatch.setattr(settings, "ADMIN_IPS", {"127.0.0.1"})
    app = create_app()

    outsider = await _get(app, "/config/data", TRUSTED, {"x-forwarded-for": REAL_CLIENT})
    assert outsider.status_code == 403

    # And a direct caller cannot claim loopback either.
    forger = await _get(app, "/config/data", REAL_CLIENT, {"x-forwarded-for": "127.0.0.1"})
    assert forger.status_code == 403
