"""Per-day session tracking, /quota/activity, /pricing and coach insights."""

from __future__ import annotations

from datetime import datetime, timedelta

import httpx
import pytest

from claude_cloak import settings, state
from claude_cloak.app import create_app
from claude_cloak.coach import _coach_record_response
from claude_cloak.coach_insights import coach_insights
from claude_cloak.quota.usage import _record_usage

USAGE = {"input_tokens": 1_000, "output_tokens": 500, "cache_read_input_tokens": 9_000}


@pytest.fixture
def client():
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app()), base_url="http://testserver"
    )


def _record(user, session, model="claude-sonnet-5", usage=USAGE):
    _record_usage(model, dict(usage), session_id=session, user_label=user)


async def test_activity_counts_sessions_per_user_per_day(client):
    _record("phong", "s1")
    _record("phong", "s1")
    _record("phong", "s2")
    _record("huy", "s3")
    async with client:
        body = (await client.get("/quota/activity")).json()

    today = body["days"][0]
    assert today["date"] == body["today"]
    assert today["sessions"] == 3
    phong = next(u for u in today["users"] if u["user_label"] == "phong")
    assert phong["sessions"] == 2
    assert phong["requests"] == 3
    assert phong["cost_per_session"] == pytest.approx(phong["cost_usd"] / 2)

    summary = next(u for u in body["users"] if u["user_label"] == "phong")
    assert summary["today"]["sessions"] == 2
    assert summary["yesterday"]["sessions"] == 0
    assert len(summary["daily_cost"]) == 14
    assert summary["daily_cost"][-1] == pytest.approx(phong["cost_usd"])


async def test_days_before_session_tracking_report_unknown_not_zero(client):
    day = (datetime.now() - timedelta(days=3)).strftime("%Y-%m-%d")
    state.quota_stats["by_day"][day] = {
        "date": day,
        "requests": 4,
        "input_tokens": 10,
        "output_tokens": 10,
        "cache_read_input_tokens": 0,
        "cache_creation_input_tokens": 0,
        "cost_usd": 1.0,
    }
    state.quota_stats["by_day_user"][day] = {
        "phong": {
            "date": day,
            "user_label": "phong",
            "requests": 4,
            "input_tokens": 10,
            "output_tokens": 10,
            "cache_read_input_tokens": 0,
            "cache_creation_input_tokens": 0,
            "cost_usd": 1.0,
        }
    }
    async with client:
        body = (await client.get("/quota/activity")).json()
        detail = (await client.get(f"/quota/activity/{day}")).json()
    old = next(d for d in body["days"] if d["date"] == day)
    assert old["sessions"] is None
    assert old["users"][0]["sessions"] is None
    assert old["users"][0]["cost_per_session"] is None
    assert detail["tracked"] is False


async def test_day_sessions_can_be_filtered_by_user(client):
    _record("phong", "s1")
    _record("huy", "s2")
    today = datetime.now().strftime("%Y-%m-%d")
    async with client:
        body = (await client.get(f"/quota/activity/{today}", params={"user": "huy"})).json()
        bad = await client.get("/quota/activity/27-09-2026")
    assert [s["session_id"] for s in body["sessions"]] == ["s2"]
    assert body["tracked"] is True
    assert bad.status_code == 400


async def test_groups_roll_users_up(client, monkeypatch):
    monkeypatch.setattr(settings, "USER_GROUPS", {"phong": "backend", "huy": "backend"})
    _record("phong", "s1")
    _record("huy", "s2")
    _record("linh", "s3")
    async with client:
        body = (await client.get("/quota/activity")).json()
    assert body["groups_configured"] is True
    groups = {g["group"]: g for g in body["groups"]}
    assert groups["backend"]["users"] == 2
    assert groups["backend"]["today"]["sessions"] == 2
    assert groups[""]["users"] == 1


def test_day_session_buckets_follow_by_day_eviction(monkeypatch):
    monkeypatch.setattr(settings, "QUOTA_MAX_DAYS", 1)
    old = (datetime.now() - timedelta(days=5)).strftime("%Y-%m-%d")
    state.quota_stats["by_day_session"][old] = {"x": {"session_id": "x"}}
    state.quota_stats["by_day"][old] = {"date": old}
    _record("phong", "s1")
    assert old not in state.quota_stats["by_day_session"]


async def test_pricing_endpoint_reports_the_table(client):
    async with client:
        body = (await client.get("/pricing")).json()
    assert body["origin"] == "bundled"
    models = {m["model"]: m for m in body["models"]}
    assert models["opus-5.5"]["input"] == 4.0
    assert "unpriced_models" in body


async def test_pricing_refresh_needs_a_remote_url(client):
    async with client:
        r = await client.post("/admin/pricing/refresh")
    assert r.status_code == 409


def test_coach_tracks_weeks_and_users():
    _coach_record_response({"Read": 2, "Edit": 1}, "end_turn", "phong")
    week = next(iter(state.coach_stats["by_week"].values()))
    assert week == {"turns": 1, "tool_results": 0, "tool_errors": 0, "reads": 2, "edits": 1}
    assert state.coach_stats["by_user"]["phong"]["reads"] == 2


def test_successor_recommendation_is_priced_from_real_tokens():
    usage = {"input_tokens": 400_000, "output_tokens": 200_000, "cache_read_input_tokens": 0}
    _record("phong", "s1", model="claude-opus-5", usage=usage)
    recs = coach_insights()["recommendations"]
    rec = next(r for r in recs if r["target"] == "opus-5" and r["kind"] == "model")
    # $5/$25 -> $4/$20: 0.4M*$1 + 0.2M*$5 saved.
    assert rec["savings_usd"] == pytest.approx(0.4 + 1.0, abs=0.01)


def test_heavy_opus_use_suggests_moving_part_of_it():
    usage = {"input_tokens": 1_000_000, "output_tokens": 400_000, "cache_read_input_tokens": 0}
    _record("phong", "s1", model="claude-opus-5-5", usage=usage)
    recs = coach_insights()["recommendations"]
    rec = next(r for r in recs if r["scope"] == "user" and r["target"] == "phong")
    # opus-5.5 $4/$20 vs sonnet-5 $2/$10 on the same tokens, 30% moved.
    assert rec["savings_usd"] == pytest.approx(0.3 * (2.0 + 4.0), abs=0.01)


def test_insights_are_empty_without_traffic():
    view = coach_insights()
    assert view["recommendations"] == []
    assert view["groups"] == []
    assert view["group_by"] == "user"


def test_daily_user_bucket_keeps_a_per_model_split():
    _record("phong", "s1", model="claude-opus-5")
    _record("phong", "s1", model="claude-sonnet-5")
    today = datetime.now().strftime("%Y-%m-%d")
    models = state.quota_stats["by_day_user"][today]["phong"]["models"]
    assert set(models) == {"opus-5", "sonnet-5"}
    assert models["opus-5"]["requests"] == 1
    assert sum(m["cost_usd"] for m in models.values()) == pytest.approx(
        state.quota_stats["by_day_user"][today]["phong"]["cost_usd"]
    )


def test_model_mix_uses_the_same_30_day_window_as_the_other_columns():
    usage = {"input_tokens": 1_000_000, "output_tokens": 400_000, "cache_read_input_tokens": 0}
    _record("phong", "s1", model="claude-opus-5", usage=usage)
    # A quota-period rollover empties the per-user buckets; the comparison
    # must not lose its model mix with them.
    state.quota_stats["by_user"]["phong"]["models"] = {}
    # A day outside the window must not count, even with a model split.
    old = (datetime.now() - timedelta(days=45)).strftime("%Y-%m-%d")
    state.quota_stats["by_day_user"][old] = {
        "phong": {
            "requests": 1,
            "cost_usd": 99.0,
            "models": {"sonnet-5": {"requests": 1, "cost_usd": 99.0}},
        }
    }
    unit = next(u for u in coach_insights()["groups"] if u["unit"] == "phong")
    assert unit["top_tier_cost_share"] == 1.0
    recs = coach_insights()["recommendations"]
    successor = next(r for r in recs if r["target"] == "opus-5")
    assert successor["savings_window"] == "30 ngày"


def test_history_retention_covers_the_eight_week_trend():
    assert settings.QUOTA_MAX_DAYS >= 8 * 7


def test_caps_hint_matches_the_format_the_parser_reads():
    from claude_cloak.config_console import CONFIG_SPECS

    spec = next(s for s in CONFIG_SPECS if s["key"] == "USER_QUOTA_CAPS")
    assert "phong:50" in spec["desc"]
    assert "=" not in spec["desc"]
