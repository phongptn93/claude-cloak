"""Alerts, cache-TTL accounting, single-parse request pipeline, HTTP/2."""

from __future__ import annotations

import json
from datetime import datetime

import httpx
import pytest

from claude_cloak import alerts, settings, state
from claude_cloak.app import build_upstream_client, create_app
from claude_cloak.quota import cache_ttl


@pytest.fixture
def client():
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app()), base_url="http://testserver"
    )


@pytest.fixture(autouse=True)
def _fresh_alert_memory():
    alerts._sent.clear()
    cache_ttl._last_turn.clear()
    yield
    alerts._sent.clear()
    cache_ttl._last_turn.clear()


# --- alerts -------------------------------------------------------------------


async def test_account_alert_fires_once_per_window(monkeypatch):
    posts = []
    hook = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda r: posts.append(json.loads(r.content)) or httpx.Response(200)
        )
    )
    monkeypatch.setattr(settings, "ALERT_WEBHOOK_URL", "https://hooks.example/x")
    monkeypatch.setattr(state.runtime, "telemetry_client", hook)
    window = [{"window": "5h", "utilization": 0.93, "reset": "2026-10-13T20:00:00"}]
    async with hook:
        alerts.check_account_limits("max-1", "acct-1", window)
        alerts.check_account_limits("max-1", "acct-1", window)  # same window: quiet
        alerts.check_account_limits("max-1", "acct-1", [{**window[0], "utilization": 0.5}])
        await alerts.drain()
    assert len(posts) == 1
    assert "max-1" in posts[0]["text"] and "93%" in posts[0]["text"]


def test_alerts_are_off_without_a_webhook(monkeypatch):
    monkeypatch.setattr(settings, "ALERT_WEBHOOK_URL", "")
    assert alerts.notify("k", "warn", "x") is False


async def test_user_cap_alerts_near_and_over(monkeypatch):
    sent = []
    monkeypatch.setattr(settings, "ALERT_WEBHOOK_URL", "https://hooks.example/x")
    monkeypatch.setattr(
        alerts, "notify", lambda key, level, text, cooldown_s=None: sent.append(key)
    )
    alerts.check_user_cap("phong", 41.0, 50.0, "2026-10")
    alerts.check_user_cap("phong", 51.0, 50.0, "2026-10")
    assert sent == ["cap:phong:2026-10:near", "cap:phong:2026-10:over"]


# --- cache TTL ------------------------------------------------------------------


def test_cache_ttl_premium_and_savings(monkeypatch):
    clock = iter([0.0, 600.0, 610.0])  # second turn after 10 min, third after 10 s
    monkeypatch.setattr(cache_ttl.time, "monotonic", lambda: next(clock))
    write_1h = {"cache_creation": {"ephemeral_1h_input_tokens": 100_000}}
    cache_ttl.record_cache_ttl_usage("s1", "opus-5.5", write_1h)
    cache_ttl.record_cache_ttl_usage("s1", "opus-5.5", {"cache_read_input_tokens": 100_000})
    cache_ttl.record_cache_ttl_usage("s1", "opus-5.5", {"cache_read_input_tokens": 100_000})
    view = cache_ttl.cache_ttl_view()
    # Opus 5.5: 1h write $8, 5m write $5, read $0.20 per MTok.
    assert view["premium_usd"] == pytest.approx(0.30)
    assert view["saved_usd"] == pytest.approx(0.48)  # only the turn after the 10-min pause
    assert view["gaps"] == {"under_5m": 1, "5m_to_1h": 1, "over_1h": 0}


def test_client_requested_1h_ttl_is_counted():
    body = {
        "system": [
            {"type": "text", "text": "x", "cache_control": {"type": "ephemeral", "ttl": "1h"}}
        ]
    }
    cache_ttl.record_client_cache_ttl(body, "v1/messages")
    cache_ttl.record_client_cache_ttl({"system": "plain"}, "v1/messages")
    assert cache_ttl.cache_ttl_view()["requests_client_1h"] == 1


# --- single-parse pipeline --------------------------------------------------------


async def test_body_is_sanitised_and_optimised_in_one_pass(client, monkeypatch):
    monkeypatch.setattr(settings, "TOKEN_SAVER_ENABLED", True)
    monkeypatch.setattr(settings, "CACHE_EXTEND_TTL", True)
    seen = {}

    def answer(req):
        seen["body"] = json.loads(req.content)
        return httpx.Response(200, json={"usage": {}, "content": []})

    upstream = httpx.AsyncClient(transport=httpx.MockTransport(answer))
    monkeypatch.setattr(state.runtime, "http_client", upstream)
    body = {
        "model": "claude-opus-5-5",
        "system": "You are helpful.",
        "messages": [{"role": "user", "content": "hi"}],
        "metadata": {"user_id": "u", "hostname": "phong-laptop"},
    }
    async with client, upstream:
        r = await client.post("/v1/messages", json=body)
    assert r.status_code == 200
    sent = seen["body"]
    assert sent["metadata"]["hostname"] != "phong-laptop"  # sanitised
    assert sent["system"][0]["cache_control"]["ttl"] == "1h"  # token saver applied
    assert state.token_saver_stats["requests_ttl_upgraded"] == 1


# --- coach cache score ------------------------------------------------------------


def test_cache_score_is_relative_to_the_team():
    from claude_cloak.coach_insights import unit_stats

    today = datetime.now().date().isoformat()

    def row(read, write):
        return {
            "requests": 10,
            "input_tokens": 0,
            "output_tokens": 0,
            "cost_usd": 1.0,
            "cache_read_input_tokens": read,
            "cache_creation_input_tokens": write,
        }

    state.quota_stats["by_day_user"][today] = {
        "a": row(97_000, 3_000),  # 3% miss
        "b": row(97_000, 3_000),
        "c": row(94_000, 6_000),  # twice the team's miss rate
    }
    scores = {u["name"]: u["cache_score"] for u in unit_stats()}
    assert scores == {"a": 100, "b": 100, "c": 50}


# --- HTTP/2 -------------------------------------------------------------------------


async def test_http2_is_opt_in(monkeypatch):
    monkeypatch.setattr(settings, "UPSTREAM_HTTP2", True)
    c = build_upstream_client()
    assert c._transport._pool._http2 is True
    await c.aclose()
