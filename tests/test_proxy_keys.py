"""Proxy keys: the second door beside ALLOWED_IPS.

The IP whitelist cannot serve a client whose address changes every hour. A key
can — which means it now decides who reaches the upstream billing surface, so
these tests pin both halves: a valid key admits an unlisted address, and
nothing else does.
"""

from __future__ import annotations

import json

import httpx
import pytest

from claude_cloak import proxy_keys, settings, state
from claude_cloak.access import parse_key_prefix
from claude_cloak.app import create_app

OUTSIDER = "198.51.100.66"
WHITELISTED = "203.0.113.5"


@pytest.fixture
def key_store(tmp_path, monkeypatch):
    """A real key file, isolated per test."""
    monkeypatch.setattr(settings, "PROXY_KEYS_PATH", str(tmp_path / ".keys.json"))
    monkeypatch.setattr(settings, "PROXY_KEYS_ENABLED", True)
    monkeypatch.setattr(settings, "PROXY_KEYS_PERSIST_INTERVAL_SECONDS", 0)
    state.proxy_keys["keys"].clear()
    state.proxy_keys["by_hash"] = {}
    return tmp_path / ".keys.json"


@pytest.fixture
def server_mode(monkeypatch):
    monkeypatch.setattr(settings, "DEPLOY_MODE", "server")
    monkeypatch.setattr(settings, "ALLOWED_NETWORKS", settings.parse_allowed_networks(WHITELISTED))
    monkeypatch.setattr(settings, "TIMING_JITTER_ENABLED", False)


async def _get(path, client_ip=OUTSIDER, headers=None):
    transport = httpx.ASGITransport(app=create_app(), client=(client_ip, 12345))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        return await c.get(path, headers=headers or {})


# ── The store ────────────────────────────────────────────────────────────


def test_a_key_is_stored_only_as_a_digest(key_store):
    secret, record = proxy_keys.create_key("phong", note="laptop 4G")
    on_disk = json.loads(key_store.read_text())
    assert secret not in key_store.read_text()
    assert on_disk["keys"][0]["hash"] == proxy_keys.hash_secret(secret)
    # The prefix is for telling two keys apart, not for reconstructing one.
    assert record["prefix"] == secret[:6]
    assert "hash" not in proxy_keys.public_view(record)


def test_verify_accepts_only_the_exact_secret(key_store):
    secret, _ = proxy_keys.create_key("phong")
    assert proxy_keys.verify_secret(secret)[0] is not None
    assert proxy_keys.verify_secret(secret[:-1] + ("A" if secret[-1] != "A" else "B")) == (
        None,
        "unknown",
    )
    assert proxy_keys.verify_secret("")[1] == "malformed"
    assert proxy_keys.verify_secret("../../etc/passwd")[1] == "malformed"


def test_a_disabled_or_expired_key_stops_working(key_store):
    secret, record = proxy_keys.create_key("phong")
    proxy_keys.update_key(record["id"], enabled=False)
    assert proxy_keys.verify_secret(secret) == (None, "disabled")

    proxy_keys.update_key(record["id"], enabled=True)
    record["expires_at"] = "2020-01-01T00:00:00"
    assert proxy_keys.verify_secret(secret) == (None, "expired")
    assert proxy_keys.key_status(record) == "expired"


def test_an_unreadable_expiry_is_treated_as_expired(key_store):
    """Fail closed: a key whose lifetime we cannot establish is not the one
    that keeps working."""
    secret, record = proxy_keys.create_key("phong")
    record["expires_at"] = "not-a-date"
    assert proxy_keys.verify_secret(secret)[1] == "expired"


def test_deleting_a_key_revokes_it_immediately(key_store):
    secret, record = proxy_keys.create_key("phong")
    assert proxy_keys.delete_key(record["id"]) is True
    assert proxy_keys.verify_secret(secret) == (None, "unknown")
    assert proxy_keys.delete_key(record["id"]) is False


def test_labels_are_validated_at_the_door(key_store):
    with pytest.raises(ValueError):
        proxy_keys.create_key("bad label")
    with pytest.raises(ValueError):
        proxy_keys.create_key("")
    with pytest.raises(ValueError):
        proxy_keys.create_key("phong", expires_in_days=99999)


def test_the_store_survives_a_restart(key_store):
    secret, record = proxy_keys.create_key("phong", note="desktop")
    state.proxy_keys["keys"].clear()
    state.proxy_keys["by_hash"] = {}
    assert proxy_keys.load_keys() is True
    found, reason = proxy_keys.verify_secret(secret)
    assert reason == "ok"
    assert found is not None
    assert found["id"] == record["id"]
    assert found["note"] == "desktop"


def test_a_corrupt_store_does_not_crash_the_proxy(key_store):
    key_store.write_text("{not json", encoding="utf-8")
    assert proxy_keys.load_keys() is False
    assert proxy_keys.list_keys() == []


# ── URL parsing ──────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/k/abc123/v1/messages", ("abc123", "/v1/messages")),
        ("/k/abc123", ("abc123", "/")),
        ("/k/abc123/", ("abc123", "/")),
        ("/k/abc123/u/phong/whoami", ("abc123", "/u/phong/whoami")),
        ("/v1/messages", (None, "/v1/messages")),
        ("/k/", (None, "/k/")),
    ],
)
def test_parse_key_prefix(path, expected):
    assert parse_key_prefix(path) == expected


def test_the_url_segment_never_shadows_a_real_route(monkeypatch):
    """A segment naming an existing route would hide it, so it is refused."""
    import importlib

    monkeypatch.setenv("PROXY_KEY_URL_SEGMENT", "config")
    fresh = importlib.reload(settings)
    assert fresh.PROXY_KEY_URL_SEGMENT == "k"
    monkeypatch.delenv("PROXY_KEY_URL_SEGMENT", raising=False)
    importlib.reload(settings)


# ── The gate ─────────────────────────────────────────────────────────────


async def test_a_valid_key_admits_an_address_the_whitelist_rejects(key_store, server_mode):
    secret, _ = proxy_keys.create_key("phong")
    assert (await _get("/health")).status_code == 403
    assert (await _get(f"/k/{secret}/health")).status_code == 200


async def test_the_header_form_works_the_same(key_store, server_mode):
    secret, _ = proxy_keys.create_key("phong")
    r = await _get("/health", headers={settings.PROXY_KEY_HEADER: secret})
    assert r.status_code == 200


async def test_a_wrong_key_is_refused_even_from_a_whitelisted_address(key_store, server_mode):
    """An explicit bad credential is an error, not a silent fallback to the
    whitelist — otherwise a typo'd key looks like it works."""
    proxy_keys.create_key("phong")
    r = await _get("/health", client_ip=WHITELISTED, headers={settings.PROXY_KEY_HEADER: "x" * 40})
    assert r.status_code == 403
    assert "proxy key" in r.json()["reason"]


async def test_a_key_is_refused_while_the_feature_is_off(key_store, server_mode, monkeypatch):
    secret, _ = proxy_keys.create_key("phong")
    monkeypatch.setattr(settings, "PROXY_KEYS_ENABLED", False)
    r = await _get(f"/k/{secret}/health")
    assert r.status_code == 403
    assert "disabled" in r.json()["reason"]


async def test_a_key_never_opens_the_admin_console(key_store, server_mode, monkeypatch):
    """The whole point of the ADMIN_IPS gate is that it is not for sale."""
    monkeypatch.setattr(settings, "ADMIN_IPS", {"127.0.0.1"})
    secret, _ = proxy_keys.create_key("phong")
    for path in (f"/k/{secret}/config", f"/k/{secret}/config/data", f"/k/{secret}/keys"):
        assert (await _get(path)).status_code == 403, path


async def test_a_key_can_be_made_to_label_without_admitting(key_store, server_mode, monkeypatch):
    monkeypatch.setattr(settings, "PROXY_KEY_BYPASS_IP_ALLOWLIST", False)
    secret, _ = proxy_keys.create_key("phong")
    assert (await _get(f"/k/{secret}/health")).status_code == 403
    assert (await _get(f"/k/{secret}/health", client_ip=WHITELISTED)).status_code == 200


async def test_the_key_never_reaches_the_upstream_path(key_store, server_mode, monkeypatch):
    """The secret is stripped before routing, so nothing downstream — logs,
    the upstream URL, the quota tap — can carry it."""
    monkeypatch.setattr(settings, "DEV_ECHO_MODE", True)
    secret, _ = proxy_keys.create_key("phong")
    transport = httpx.ASGITransport(app=create_app(), client=(OUTSIDER, 12345))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        r = await c.post(
            f"/k/{secret}/v1/messages", json={"model": "claude-opus-5", "messages": []}
        )
    assert r.status_code == 200
    assert state.quota_stats["by_user"]["phong"]["requests"] == 1


async def test_whoami_reports_the_key_identity(key_store, server_mode):
    secret, record = proxy_keys.create_key("phong")
    body = (await _get(f"/k/{secret}/whoami")).json()
    assert body["label"] == "phong"
    assert body["authenticated_by"] == "proxy_key"
    assert body["proxy_key_id"] == record["id"]


async def test_a_key_outranks_a_url_label(key_store, server_mode, monkeypatch):
    """Otherwise a key holder could bill their traffic to someone else."""
    monkeypatch.setattr(settings, "DEV_ECHO_MODE", True)
    secret, _ = proxy_keys.create_key("phong")

    body = (await _get(f"/k/{secret}/u/huy/whoami")).json()
    assert body == {**body, "label": "phong", "url_label": "huy"}

    transport = httpx.ASGITransport(app=create_app(), client=(OUTSIDER, 12345))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        await c.post(
            f"/k/{secret}/u/huy/v1/messages", json={"model": "claude-opus-5", "messages": []}
        )
    assert "huy" not in state.quota_stats["by_user"]
    assert state.quota_stats["by_user"]["phong"]["requests"] == 1


async def test_using_a_key_is_recorded(key_store, server_mode):
    secret, record = proxy_keys.create_key("phong")
    await _get(f"/k/{secret}/health")
    assert record["use_count"] == 1
    assert record["last_used_ip"] == OUTSIDER
    assert record["last_used_at"]


# ── The console ──────────────────────────────────────────────────────────


@pytest.fixture
def admin_client(monkeypatch):
    monkeypatch.setattr(settings, "ADMIN_TOKEN", "test-admin-token")
    monkeypatch.setattr(settings, "ADMIN_IPS", {"127.0.0.1"})
    transport = httpx.ASGITransport(app=create_app(), client=("127.0.0.1", 12345))
    return httpx.AsyncClient(transport=transport, base_url="http://testserver")


async def test_the_page_and_its_data_render(key_store, admin_client):
    async with admin_client as c:
        page = await c.get("/keys")
        assert page.status_code == 200
        assert page.text.lstrip().startswith("<!doctype html>")
        data = await c.get("/keys/data")
        assert data.status_code == 200
        assert data.json()["editable"] is False  # not signed in yet


async def test_issuing_a_key_requires_a_signed_in_admin(key_store, admin_client):
    async with admin_client as c:
        denied = await c.post("/keys/create", json={"label": "phong"})
        assert denied.status_code == 401
        assert not proxy_keys.list_keys()

        assert (
            await c.post("/config/login", json={"token": "test-admin-token"})
        ).status_code == 200

        created = await c.post("/keys/create", json={"label": "phong", "expires_in_days": 30})
        assert created.status_code == 200
        body = created.json()
        assert body["ok"] is True
        # The plaintext appears here and nowhere else.
        assert proxy_keys.verify_secret(body["secret"])[1] == "ok"

        listed = (await c.get("/keys/data")).json()
        assert [k["id"] for k in listed["keys"]] == [body["key"]["id"]]
        assert body["secret"] not in json.dumps(listed)

        toggled = await c.post("/keys/update", json={"id": body["key"]["id"], "enabled": False})
        assert toggled.json()["key"]["status"] == "disabled"

        assert (await c.post("/keys/delete", json={"id": body["key"]["id"]})).status_code == 200
        assert not proxy_keys.list_keys()


async def test_the_api_rejects_a_bad_label_and_an_unknown_id(key_store, admin_client):
    async with admin_client as c:
        await c.post("/config/login", json={"token": "test-admin-token"})
        bad = await c.post("/keys/create", json={"label": "not a label"})
        assert bad.status_code == 400
        missing = await c.post("/keys/update", json={"id": "abcdef123456", "enabled": True})
        assert missing.status_code == 404


async def test_the_console_is_not_reachable_from_a_non_admin_ip(key_store, monkeypatch):
    monkeypatch.setattr(settings, "ADMIN_IPS", {"10.9.9.9"})
    assert (await _get("/keys")).status_code == 403
    assert (await _get("/keys/data")).status_code == 403
