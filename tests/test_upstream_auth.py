"""Upstream auth: the client's own credential by default, a proxy-held one
when UPSTREAM_AUTH_MODE=server or a proxy key says so.

What reaches Anthropic decides who is billed, so each test asserts on the
headers the upstream actually received.
"""

from __future__ import annotations

import httpx
import pytest

from claude_cloak import proxy_keys, settings, state
from claude_cloak.app import create_app
from claude_cloak.upstream_auth import OAUTH_BETA

OAUTH = "sk-ant-oat01-server-subscription-token-abcd"
API_KEY = "sk-ant-api03-server-api-key-wxyz"
CLIENT_HEADERS = {
    "authorization": "Bearer sk-ant-oat01-client-own-login",
    "anthropic-beta": f"{OAUTH_BETA},interleaved-thinking-2025-05-14",
}


@pytest.fixture
def upstream(monkeypatch):
    """Capture what the proxy sends upstream."""
    seen: list[httpx.Request] = []

    def answer(req):
        seen.append(req)
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={"model": "claude-haiku-5-5", "usage": {"input_tokens": 10, "output_tokens": 1}},
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(answer))
    monkeypatch.setattr(state.runtime, "http_client", client)
    monkeypatch.setattr(settings, "TIMING_JITTER_ENABLED", False)
    monkeypatch.setattr(settings, "UPSTREAM_CREDENTIALS", {"team-max": OAUTH, "api": API_KEY})
    return seen


@pytest.fixture
def keys(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "PROXY_KEYS_PATH", str(tmp_path / ".keys.json"))
    monkeypatch.setattr(settings, "PROXY_KEYS_ENABLED", True)
    state.proxy_keys["keys"].clear()
    state.proxy_keys["by_hash"] = {}


async def _send(path="/v1/messages", headers=CLIENT_HEADERS):
    transport = httpx.ASGITransport(app=create_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        return await c.post(path, json={"model": "x", "messages": []}, headers=headers)


def _betas(req: httpx.Request) -> list[str]:
    return [b for b in req.headers.get("anthropic-beta", "").split(",") if b]


async def test_by_default_the_clients_own_login_is_forwarded(upstream):
    assert (await _send()).status_code == 200
    req = upstream[0]
    assert req.headers["authorization"] == CLIENT_HEADERS["authorization"]
    assert "x-api-key" not in req.headers


async def test_server_mode_replaces_the_client_login_with_the_default_credential(
    upstream, monkeypatch
):
    monkeypatch.setattr(settings, "UPSTREAM_AUTH_MODE", "server")
    assert (await _send()).status_code == 200
    req = upstream[0]
    assert req.headers["authorization"] == f"Bearer {OAUTH}"
    assert OAUTH_BETA in _betas(req)
    assert "interleaved-thinking-2025-05-14" in _betas(req)
    # Billed to the server credential, shown by its name.
    accounts = state.quota_stats["accounts"]
    assert set(accounts) == {"cred:team-max"}


async def test_an_api_key_credential_drops_the_oauth_beta(upstream, monkeypatch):
    monkeypatch.setattr(settings, "UPSTREAM_AUTH_MODE", "server")
    monkeypatch.setattr(settings, "UPSTREAM_CREDENTIAL_DEFAULT", "api")
    await _send()
    req = upstream[0]
    assert req.headers["x-api-key"] == API_KEY
    assert "authorization" not in req.headers
    assert _betas(req) == ["interleaved-thinking-2025-05-14"]


async def test_a_key_can_choose_server_auth_and_its_credential(upstream, keys):
    secret, _ = proxy_keys.create_key("phong", auth_mode="server", credential="api")
    other, _ = proxy_keys.create_key("huy")
    await _send(f"/k/{secret}/v1/messages")
    await _send(f"/k/{other}/v1/messages")
    assert upstream[0].headers["x-api-key"] == API_KEY
    assert upstream[1].headers["authorization"] == CLIENT_HEADERS["authorization"]


async def test_a_key_can_keep_the_client_login_under_server_mode(upstream, keys, monkeypatch):
    monkeypatch.setattr(settings, "UPSTREAM_AUTH_MODE", "server")
    secret, _ = proxy_keys.create_key("phong", auth_mode="client")
    await _send(f"/k/{secret}/v1/messages")
    assert upstream[0].headers["authorization"] == CLIENT_HEADERS["authorization"]


async def test_server_mode_without_a_credential_fails_instead_of_falling_back(
    upstream, monkeypatch
):
    monkeypatch.setattr(settings, "UPSTREAM_AUTH_MODE", "server")
    monkeypatch.setattr(settings, "UPSTREAM_CREDENTIALS", {})
    r = await _send()
    assert r.status_code == 503
    assert r.json()["error"]["type"] == "upstream_auth_unavailable"
    assert upstream == []


def test_a_key_cannot_name_an_unknown_credential(keys, monkeypatch):
    monkeypatch.setattr(settings, "UPSTREAM_CREDENTIALS", {"team-max": OAUTH})
    with pytest.raises(ValueError):
        proxy_keys.create_key("phong", auth_mode="server", credential="nope")
    with pytest.raises(ValueError):
        proxy_keys.create_key("phong", auth_mode="sometimes")
    _, rec = proxy_keys.create_key("phong", auth_mode="server", credential="team-max")
    assert proxy_keys.public_view(rec)["credential"] == "team-max"
    proxy_keys.update_key(rec["id"], auth_mode="inherit", credential="")
    assert proxy_keys.public_view(rec)["auth_mode"] == "inherit"


async def test_no_secret_is_exposed_by_the_key_console(upstream, keys, monkeypatch):
    from claude_cloak.upstream_auth import credentials_view

    view = credentials_view()
    assert [c["name"] for c in view] == ["team-max", "api"]
    assert view[0]["kind"] == "oauth" and view[1]["kind"] == "api_key"
    assert OAUTH not in repr(view) and API_KEY not in repr(view)
