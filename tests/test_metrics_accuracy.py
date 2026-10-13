"""Dashboard figures must measure what their labels say."""

from __future__ import annotations

import json

import httpx
import pytest

from claude_cloak import settings, state, tokens
from claude_cloak.app import create_app
from claude_cloak.coach import _compute_coach_view
from claude_cloak.quota.activity import _empty, _finish
from claude_cloak.routes.quota import _unified_windows


@pytest.fixture
def client():
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app()), base_url="http://testserver"
    )


def test_subscription_rate_limits_are_reported():
    rl = {
        "unified-status": "allowed",
        "unified-5h-utilization": "0.42",
        "unified-5h-reset": "1760000000",
        "unified-5h-status": "allowed",
        "unified-7d-utilization": "0.9",
    }
    windows = {w["window"]: w for w in _unified_windows(rl)}
    assert windows["5h"]["utilization"] == pytest.approx(0.42)
    assert windows["5h"]["reset"].startswith("20")  # unix seconds -> ISO
    assert windows["7d"]["reset"] is None


def test_cache_writes_count_as_cache_misses():
    # Typical Claude Code turn: a few fresh tokens, a big write, no reads yet.
    state.quota_stats["usage_total"].update(
        input_tokens=10, cache_read_input_tokens=30_000, cache_creation_input_tokens=70_000
    )
    assert _compute_coach_view()["cache_hit_rate"] == pytest.approx(0.3, abs=0.001)

    row = _empty()
    row.update(input_tokens=10, cache_read_input_tokens=30_000, cache_creation_input_tokens=70_000)
    assert _finish(row)["cache_hit_rate"] == pytest.approx(0.3, abs=0.001)


def test_tokens_saved_counts_only_truncated_text(monkeypatch):
    monkeypatch.setattr(settings, "TOKEN_SAVER_ENABLED", True)
    monkeypatch.setattr(settings, "CACHE_EXTEND_TTL", False)
    monkeypatch.setattr(settings, "TOOL_RESULT_TRUNCATE", True)
    monkeypatch.setattr(settings, "TOOL_RESULT_KEEP_RECENT", 0)
    # Escaped non-ASCII and whitespace shrink on re-serialisation; that is
    # not a token saving.
    body = b'{"messages": [{"role": "user", "content": "\\u00e9\\u00e9\\u00e9\\u00e9"}]}'
    assert tokens.optimize_tokens(body, "application/json", "v1/messages") == body
    assert state.token_saver_stats["bytes_saved"] == 0

    big = "x" * 20_000
    body = (
        b'{"messages":[{"role":"user","content":[{"type":"tool_result","content":"'
        + big.encode()
        + b'"}]}]}'
    )
    out = json.loads(tokens.optimize_tokens(body, "application/json", "v1/messages"))
    kept = out["messages"][0]["content"][0]["content"]
    assert state.token_saver_stats["bytes_saved"] == len(big) - len(kept)


class _DropsMidStream(httpx.AsyncByteStream):
    async def __aiter__(self):
        yield b'event: message_start\ndata: {"type":"message_start"}\n\n'
        raise httpx.ReadError("connection reset")


async def test_upstream_drop_mid_stream_is_counted_and_reported(client, monkeypatch):
    upstream = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda req: httpx.Response(
                200, headers={"content-type": "text/event-stream"}, stream=_DropsMidStream()
            )
        )
    )
    monkeypatch.setattr(state.runtime, "http_client", upstream)
    async with client, upstream:
        r = await client.post(
            "/v1/messages",
            content=b'{"model":"claude-x","stream":true,"messages":[]}',
            headers={"content-type": "application/json"},
        )
    assert r.status_code == 200
    assert b"upstream connection lost mid-stream" in r.content
    assert state.stream_stats["upstream_errors"] == 1
    assert state.stream_stats["streams_completed"] == 0


def test_oversized_context_is_flagged_with_a_saving():
    from datetime import datetime

    from claude_cloak.coach_insights import coach_insights

    today = datetime.now().date().isoformat()

    def row(requests, context):
        model = {
            "requests": requests,
            "input_tokens": 0,
            "output_tokens": 0,
            "cache_read_input_tokens": requests * context,
            "cache_creation_input_tokens": 0,
            "cost_usd": 1.0,
        }
        return {**model, "models": {"opus-5.5": dict(model)}}

    state.quota_stats["by_day_user"][today] = {
        "lean": row(500, 100_000),
        "typical": row(500, 120_000),
        "heavy": row(500, 500_000),
    }
    view = coach_insights()
    ctx = {g["name"]: g["context_per_request"] for g in view["groups"]}
    assert ctx["heavy"] == 500_000
    flagged = [r["target"] for r in view["recommendations"] if r["kind"] == "context"]
    assert flagged == ["heavy"]
