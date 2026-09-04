"""Body scrubbing, telemetry blocking, and the token saver."""

from __future__ import annotations

import json
from typing import Any

from claude_cloak import sanitize, settings, tokens


def test_is_blocked_path():
    assert sanitize.is_blocked_path("v1/telemetry")
    assert sanitize.is_blocked_path("V1/Analytics/batch")
    assert sanitize.is_blocked_path("sentry/store")
    assert not sanitize.is_blocked_path("v1/messages")


def test_sanitize_body_replaces_device_fields_consistently():
    body = json.dumps({"machine_id": "REAL", "prompt": "keep me"}).encode()
    once = sanitize.sanitize_body(body, "application/json")
    twice = sanitize.sanitize_body(body, "application/json")
    data = json.loads(once)
    assert data["machine_id"] != "REAL"
    assert data["prompt"] == "keep me"
    assert once == twice, "derived IDs must be stable for the same input"


def test_sanitize_body_leaves_non_json_untouched():
    raw = b"not json at all"
    assert sanitize.sanitize_body(raw, "text/plain") == raw
    assert sanitize.sanitize_body(b"", "application/json") == b""


def test_head_tail_truncate_keeps_both_ends(monkeypatch):
    monkeypatch.setattr(settings, "TOOL_RESULT_HEAD_BYTES", 10)
    monkeypatch.setattr(settings, "TOOL_RESULT_TAIL_BYTES", 5)
    out = tokens._head_tail_truncate("A" * 100 + "B" * 100)
    assert out.startswith("A" * 10)
    assert out.endswith("B" * 5)
    assert len(out) < 200


def test_cache_breakpoints_are_counted_and_capped(monkeypatch):
    monkeypatch.setattr(settings, "MAX_CACHE_BREAKPOINTS", 4)
    data = {
        "system": [{"type": "text", "text": "sys", "cache_control": {"type": "ephemeral"}}],
        "tools": [{"name": "t", "cache_control": {"type": "ephemeral"}}],
        "messages": [],
    }
    assert tokens._count_cache_breakpoints(data) == 2

    full: dict[str, Any] = {
        "system": [
            {"type": "text", "text": str(i), "cache_control": {"type": "ephemeral"}}
            for i in range(4)
        ],
        "messages": [],
    }
    assert tokens._count_cache_breakpoints(full) == 4
    # At the cap every existing breakpoint is upgraded to 1h, but no NEW one
    # is added — the count must stay at the cap.
    upgraded, _ = tokens._apply_cache_breakpoints(full)
    assert upgraded == 4
    assert tokens._count_cache_breakpoints(full) == 4
    blocks: list[dict[str, Any]] = full["system"]
    assert all(b["cache_control"]["ttl"] == settings.CACHE_TTL_LONG for b in blocks)


def test_optimize_tokens_is_a_noop_off_the_messages_path():
    body = json.dumps({"system": "x"}).encode()
    assert tokens.optimize_tokens(body, "application/json", "v1/complete") == body


def test_cache_ttl_beta_error_detection():
    payload = json.dumps(
        {"error": {"message": "extended-cache-ttl-2025-04-11 is not supported"}}
    ).encode()
    assert tokens._looks_like_cache_ttl_beta_error(payload)
    assert not tokens._looks_like_cache_ttl_beta_error(b'{"error":{"message":"overloaded"}}')


def test_inject_cache_ttl_beta_appends_without_duplicating(monkeypatch):
    monkeypatch.setattr(settings, "CACHE_EXTEND_TTL", True)
    monkeypatch.setattr(settings, "TOKEN_SAVER_ENABLED", True)
    headers = {"anthropic-beta": "other-beta"}
    tokens.inject_cache_ttl_beta(headers)
    tokens.inject_cache_ttl_beta(headers)
    assert headers["anthropic-beta"].count(settings.CACHE_TTL_BETA) == 1
    assert "other-beta" in headers["anthropic-beta"]
