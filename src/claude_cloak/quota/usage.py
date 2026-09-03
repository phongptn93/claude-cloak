"""Rate-limit header capture and per-response usage/cost recording."""

from __future__ import annotations

from datetime import datetime

from .. import settings, state
from ..loki import _loki_enqueue
from ..pricing import _compute_cost, _normalize_model_key
from ..terminal import CYAN, DIM, RESET, log
from .persist import (
    _check_monthly_reset,
    _evict_by_day_user_to_match_by_day,
    _evict_oldest,
    _save_quota_stats,
)
from .users import record_user_usage


def _record_rate_limits(headers) -> None:
    """Capture anthropic-ratelimit-* and retry-after headers from a response."""
    if not settings.QUOTA_TRACKING_ENABLED:
        return
    latest = {}
    for k, v in headers.items():
        kl = k.lower()
        if kl.startswith("anthropic-ratelimit-"):
            latest[kl[len("anthropic-ratelimit-") :]] = v
        elif kl == "retry-after":
            latest["retry-after"] = v
    if latest:
        state.quota_stats["rate_limits"] = latest
        state.quota_stats["rate_limits_updated_at"] = datetime.now().isoformat(timespec="seconds")


def _record_usage(
    model: str | None,
    usage: dict,
    session_id: str | None = None,
    duration_ms: int | None = None,
    user_label: str | None = None,
) -> None:
    """Accumulate a single response's usage into quota_stats and log it.

    `session_id` is the original `x-claude-code-session-id` from the incoming
    request (BEFORE the proxy rewrites it to the locked identity), so each
    device's session shows up separately. `duration_ms` is the total wall
    time including streaming, used only for Loki shipping.
    """
    if not settings.QUOTA_TRACKING_ENABLED or not usage:
        return

    _check_monthly_reset()
    model_key = _normalize_model_key(model)
    cost = _compute_cost(model_key, usage)

    # Surface models we have no published price for — they are costed at the
    # PRICING_FALLBACK rate, which is an estimate, not the real invoice.
    if model_key == "unknown" and model:
        um = state.quota_stats["unpriced_models"]
        um[model] = um.get(model, 0) + 1
        if len(um) > 20:  # keep the map bounded; drop the least-seen entry
            um.pop(min(um, key=um.get), None)

    cache_creation = usage.get("cache_creation")
    cc = cache_creation if isinstance(cache_creation, dict) else {}
    cw5 = cc.get("ephemeral_5m_input_tokens", 0) or 0
    cw1 = cc.get("ephemeral_1h_input_tokens", 0) or 0

    in_t = usage.get("input_tokens", 0) or 0
    out_t = usage.get("output_tokens", 0) or 0
    cr_t = usage.get("cache_read_input_tokens", 0) or 0
    cw_t = usage.get("cache_creation_input_tokens", 0) or 0

    totals = state.quota_stats["usage_total"]
    totals["input_tokens"] += in_t
    totals["output_tokens"] += out_t
    totals["cache_creation_input_tokens"] += cw_t
    totals["cache_creation_5m_input_tokens"] += cw5
    totals["cache_creation_1h_input_tokens"] += cw1
    totals["cache_read_input_tokens"] += cr_t

    state.quota_stats["cost_usd_total"] += cost
    state.quota_stats["messages_requests"] += 1
    now_iso = datetime.now().isoformat(timespec="seconds")
    state.quota_stats["last_request_at"] = now_iso

    bucket = state.quota_stats["by_model"].setdefault(
        model_key,
        {
            "model": model_key,
            "requests": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "cache_creation_input_tokens": 0,
            "cache_read_input_tokens": 0,
            "cost_usd": 0.0,
        },
    )
    bucket["requests"] += 1
    bucket["input_tokens"] += in_t
    bucket["output_tokens"] += out_t
    bucket["cache_creation_input_tokens"] += cw_t
    bucket["cache_read_input_tokens"] += cr_t
    bucket["cost_usd"] += cost

    if session_id:
        sb = state.quota_stats["by_session"].setdefault(
            session_id,
            {
                "session_id": session_id,
                "user_label": user_label or "",
                "requests": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "cache_creation_input_tokens": 0,
                "cache_read_input_tokens": 0,
                "cost_usd": 0.0,
                "models": {},
                "first_seen": now_iso,
                "last_seen": now_iso,
            },
        )
        # Always refresh user_label — a session may legitimately move between
        # users (e.g. URL prefix changes), or older buckets predate this field.
        if user_label:
            sb["user_label"] = user_label
        sb["requests"] += 1
        sb["input_tokens"] += in_t
        sb["output_tokens"] += out_t
        sb["cache_creation_input_tokens"] += cw_t
        sb["cache_read_input_tokens"] += cr_t
        sb["cost_usd"] += cost
        sb["last_seen"] = now_iso
        sb["models"][model_key] = sb["models"].get(model_key, 0) + 1
        _evict_oldest("by_session", "last_seen", settings.QUOTA_MAX_SESSIONS)

    today = datetime.now().strftime("%Y-%m-%d")
    db = state.quota_stats["by_day"].setdefault(
        today,
        {
            "date": today,
            "requests": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "cache_creation_input_tokens": 0,
            "cache_read_input_tokens": 0,
            "cost_usd": 0.0,
        },
    )
    db["requests"] += 1
    db["input_tokens"] += in_t
    db["output_tokens"] += out_t
    db["cache_creation_input_tokens"] += cw_t
    db["cache_read_input_tokens"] += cr_t
    db["cost_usd"] += cost
    _evict_oldest("by_day", "date", settings.QUOTA_MAX_DAYS)

    if user_label:
        record_user_usage(user_label, usage, cost, model_key=model_key)

    # by_day_user — same per-day aggregation as by_day but split per user.
    if user_label:
        day_users = state.quota_stats["by_day_user"].setdefault(today, {})
        dub = day_users.setdefault(
            user_label,
            {
                "date": today,
                "user_label": user_label,
                "requests": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "cache_read_input_tokens": 0,
                "cache_creation_input_tokens": 0,
                "cost_usd": 0.0,
            },
        )
        dub["requests"] += 1
        dub["input_tokens"] += in_t
        dub["output_tokens"] += out_t
        dub["cache_read_input_tokens"] += cr_t
        dub["cache_creation_input_tokens"] += cw_t
        dub["cost_usd"] += cost
        # Cap dates the same way by_day is capped, so the two stay in lockstep.
        _evict_by_day_user_to_match_by_day()

    log(
        f"           {DIM}usage: {RESET}{CYAN}{model_key}{RESET} "
        f"{DIM}in={in_t} out={out_t} cache_r={cr_t} cache_w={cw_t} "
        f"cost=${cost:.4f}{RESET}"
    )

    if settings.LOKI_ENABLED:
        _loki_enqueue(
            "usage",
            {
                "conversation_id": session_id or "",
                "input_tokens": in_t,
                "output_tokens": out_t,
                "cache_read_tokens": cr_t,
                "cache_creation_tokens": cw_t,
                "cache_creation_5m_tokens": cw5,
                "cache_creation_1h_tokens": cw1,
                "estimated_tokens": in_t + out_t + cr_t + cw_t,
                "cost_usd": round(cost, 6),
                "duration_ms": duration_ms,
            },
            model=model_key,
        )

    _save_quota_stats()
