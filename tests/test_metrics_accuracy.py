"""Dashboard figures must measure what their labels say."""

from __future__ import annotations

import json

import httpx
import pytest

from claude_cloak import settings, state, tokens
from claude_cloak.app import create_app
from claude_cloak.coach import _compute_coach_view
from claude_cloak.quota.accounts import unified_windows as _unified_windows
from claude_cloak.quota.activity import _empty, _finish


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


# --- several Claude accounts behind one proxy -------------------------------

ACCT_A = "3f2a9c1d-1111-4222-8333-444455556666"
ACCT_B = "b71e0f44-aaaa-4bbb-8ccc-ddddeeeeffff"


def test_account_is_read_from_claude_code_metadata():
    from claude_cloak.quota.accounts import account_from_body

    legacy = json.dumps(
        {"metadata": {"user_id": f"user_abc123_account_{ACCT_A}_session_{ACCT_B}"}}
    ).encode()
    assert account_from_body(legacy, "application/json", "v1/messages") == ACCT_A
    newer = json.dumps(
        {"metadata": {"user_id": json.dumps({"device_id": "x", "account_uuid": ACCT_B})}}
    ).encode()
    assert account_from_body(newer, "application/json", "v1/messages") == ACCT_B
    assert account_from_body(b'{"messages":[]}', "application/json", "v1/messages") is None


async def test_rate_limits_and_spend_are_kept_per_account(client, monkeypatch):
    monkeypatch.setattr(settings, "ACCOUNT_LABELS", {"3f2a9c1d": "max-1"})
    utilization = {ACCT_A: "0.10", ACCT_B: "0.85"}

    def answer(req):
        acct = ACCT_A if ACCT_A.encode() in req.content else ACCT_B
        return httpx.Response(
            200,
            headers={
                "content-type": "application/json",
                "anthropic-ratelimit-unified-5h-utilization": utilization[acct],
                "anthropic-ratelimit-unified-5h-reset": "1760000000",
            },
            json={
                "model": "claude-haiku-5-5",
                "usage": {"input_tokens": 1000, "output_tokens": 100},
                "content": [],
            },
        )

    upstream = httpx.AsyncClient(transport=httpx.MockTransport(answer))
    monkeypatch.setattr(state.runtime, "http_client", upstream)
    async with client, upstream:
        for acct in (ACCT_A, ACCT_B, ACCT_A):
            body = {
                "model": "x",
                "messages": [],
                "metadata": {"user_id": f"user_h_account_{acct}_session_s"},
            }
            r = await client.post("/v1/messages", json=body)
            assert r.status_code == 200
        accounts = {a["label"]: a for a in (await client.get("/quota")).json()["accounts"]}

    assert set(accounts) == {"max-1", "b71e0f44"}
    assert accounts["max-1"]["requests"] == 2
    assert accounts["max-1"]["rate_limits"]["unified"][0]["utilization"] == pytest.approx(0.10)
    assert accounts["b71e0f44"]["rate_limits"]["unified"][0]["utilization"] == pytest.approx(0.85)


# --- pricing ------------------------------------------------------------------


def test_new_models_are_priced_not_costed_at_the_fallback():
    from claude_cloak.pricing import _compute_cost, _normalize_model_key

    assert _normalize_model_key("claude-haiku-5-5") == "haiku-5.5"
    assert _normalize_model_key("claude-sonnet-5-5") == "sonnet-5.5"
    short = {"input_tokens": 50_000, "output_tokens": 1_000}
    assert _compute_cost("haiku-5.5", short) == pytest.approx((50_000 * 0.10 + 1_000 * 0.50) / 1e6)
    # Over 100K prompt tokens (cache reads included) the long-context card applies.
    long = {"input_tokens": 1_000, "cache_read_input_tokens": 150_000, "output_tokens": 1_000}
    expected = (1_000 * 0.50 + 150_000 * 0.05 + 1_000 * 2.50) / 1e6
    assert _compute_cost("haiku-5.5", long) == pytest.approx(expected)


def test_long_context_rates_are_validated():
    from claude_cloak.pricing import PricingError, parse_pricing

    tiers = {"input": 1, "output": 2, "cache_write_5m": 1, "cache_write_1h": 2, "cache_read": 0.1}
    bad = {"schema": 1, "models": {"haiku-9": [{**tiers, "long_context": {**tiers}}]}}
    with pytest.raises(PricingError):
        parse_pricing(bad)
