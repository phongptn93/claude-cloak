"""End-to-end checks against the real ASGI app."""

from __future__ import annotations

import json

import httpx
import pytest

from claude_cloak import env as env_module
from claude_cloak import settings, state
from claude_cloak.app import create_app


@pytest.fixture
def client():
    app = create_app()
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://testserver")


async def test_stats_endpoints_answer(client):
    async with client:
        for path in ("/health", "/quota", "/quota/users", "/coach"):
            r = await client.get(path)
            assert r.status_code == 200, path
            assert isinstance(r.json(), dict)


async def test_pages_render(client):
    async with client:
        for path in ("/dashboard", "/config"):
            r = await client.get(path)
            assert r.status_code == 200
            assert r.text.lstrip().startswith("<!doctype html>")


async def test_config_is_read_only_without_a_token(client, monkeypatch):
    monkeypatch.setattr(settings, "ADMIN_TOKEN", "")
    async with client:
        r = await client.get("/config/data")
        assert r.status_code == 200
        assert r.json()["editable"] is False

        # No ADMIN_TOKEN configured => no session can exist => 401, never applied.
        r = await client.post("/config/apply", json={"changes": {"COACH_ENABLED": False}})
        assert r.status_code == 401
        assert settings.COACH_ENABLED is True


async def test_admin_paths_reject_a_non_admin_ip(client, monkeypatch):
    monkeypatch.setattr(settings, "ADMIN_IPS", {"10.9.9.9"})
    async with client:
        r = await client.get("/config/data")
        assert r.status_code == 403


async def test_server_mode_blocks_an_unlisted_ip(client, monkeypatch):
    monkeypatch.setattr(settings, "DEPLOY_MODE", "server")
    monkeypatch.setattr(settings, "ALLOWED_NETWORKS", settings.parse_allowed_networks("10.0.0.1"))
    async with client:
        assert (await client.get("/health")).status_code == 403


async def test_telemetry_paths_are_blocked_not_forwarded(client):
    before = state.runtime.blocked_requests_count
    async with client:
        r = await client.post("/v1/telemetry", json={"machine_id": "x"})
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}
    assert state.runtime.blocked_requests_count == before + 1


async def test_dev_echo_mode_answers_without_an_upstream(client, monkeypatch):
    monkeypatch.setattr(settings, "DEV_ECHO_MODE", True)
    monkeypatch.setattr(settings, "TIMING_JITTER_ENABLED", False)
    monkeypatch.setattr(state.runtime, "http_client", None)  # proves no upstream call
    async with client:
        r = await client.post(
            "/v1/messages",
            json={"model": "claude-opus-5", "messages": [{"role": "user", "content": "hi"}]},
        )
    assert r.status_code == 200
    body = r.json()
    assert body["model"] == settings.DEV_ECHO_MODEL
    assert body["usage"]["input_tokens"] == settings.DEV_ECHO_INPUT_TOKENS


async def test_dev_echo_mode_streams_anthropic_shaped_sse(client, monkeypatch):
    monkeypatch.setattr(settings, "DEV_ECHO_MODE", True)
    monkeypatch.setattr(settings, "TIMING_JITTER_ENABLED", False)
    async with client:
        r = await client.post(
            "/v1/messages",
            json={"model": "claude-opus-5", "stream": True, "messages": []},
        )
    assert r.status_code == 200
    assert "text/event-stream" in r.headers["content-type"]
    events = [line for line in r.text.splitlines() if line.startswith("event: ")]
    assert events[0] == "event: message_start"
    assert events[-1] == "event: message_stop"
    payloads = [json.loads(line[6:]) for line in r.text.splitlines() if line.startswith("data: ")]
    assert any(p.get("type") == "message_delta" for p in payloads)


async def test_dev_echo_records_usage_and_cost(client, monkeypatch):
    monkeypatch.setattr(settings, "DEV_ECHO_MODE", True)
    monkeypatch.setattr(settings, "QUOTA_TRACKING_ENABLED", True)
    monkeypatch.setattr(settings, "TIMING_JITTER_ENABLED", False)
    before = state.quota_stats["usage_total"]["input_tokens"]
    async with client:
        await client.post("/v1/messages", json={"model": "claude-opus-5", "messages": []})
    after = state.quota_stats["usage_total"]["input_tokens"]
    assert after == before + settings.DEV_ECHO_INPUT_TOKENS


def test_generated_session_secret_is_persisted_once(tmp_path, monkeypatch):
    """A regenerated secret invalidates every admin session on restart.

    Server mode disables identity capture, which used to be the only code
    path that saved it, so a shared deployment rotated the secret on every
    start — including the restart each certificate renewal triggers.
    """
    from claude_cloak import app as app_module

    env_file = tmp_path / ".env"
    env_file.write_text("LOCAL_PORT=9999\n", encoding="utf-8")
    monkeypatch.setattr(env_module, "ENV_PATH", str(env_file))
    monkeypatch.setattr(app_module, "ENV_PATH", str(env_file))
    monkeypatch.setattr(settings, "SESSION_SECRET", "a" * 64)
    monkeypatch.setattr(settings, "SESSION_SECRET_GENERATED", True)

    app_module.persist_generated_session_secret()
    assert f"SESSION_SECRET={'a' * 64}" in env_file.read_text()
    assert settings.SESSION_SECRET_GENERATED is False

    # Second start must be a no-op, not a rotation.
    monkeypatch.setattr(settings, "SESSION_SECRET", "b" * 64)
    app_module.persist_generated_session_secret()
    assert f"SESSION_SECRET={'a' * 64}" in env_file.read_text()


def test_a_configured_session_secret_is_never_rewritten(tmp_path, monkeypatch):
    from claude_cloak import app as app_module

    env_file = tmp_path / ".env"
    env_file.write_text("SESSION_SECRET=operator-chose-this\n", encoding="utf-8")
    monkeypatch.setattr(env_module, "ENV_PATH", str(env_file))
    monkeypatch.setattr(settings, "SESSION_SECRET_GENERATED", False)
    app_module.persist_generated_session_secret()
    assert env_file.read_text() == "SESSION_SECRET=operator-chose-this\n"
