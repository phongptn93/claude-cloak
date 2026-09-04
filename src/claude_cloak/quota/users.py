"""Per-user spend buckets and cap enforcement."""

from __future__ import annotations

from datetime import datetime

from .. import settings, state
from ..access import cap_for_label, current_user_period_key


def _new_user_bucket(label: str) -> dict:
    return {
        "label": label,
        "cap_usd": cap_for_label(label),
        "period": settings.USER_QUOTA_PERIOD,
        "period_key": current_user_period_key(),
        "period_start": datetime.now().isoformat(timespec="seconds"),
        "cost_usd": 0.0,
        "requests": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_read_input_tokens": 0,
        "cache_creation_input_tokens": 0,
        "blocked_count": 0,
        "models": {},  # model_key -> {requests, input_tokens, output_tokens, cache_*, cost_usd}
        "first_seen": datetime.now().isoformat(timespec="seconds"),
        "last_seen": None,
    }


def _reset_user_bucket(bucket: dict, period_key: str) -> None:
    """Zero out a user's counters at the start of a new period."""
    bucket["period_key"] = period_key
    bucket["period_start"] = datetime.now().isoformat(timespec="seconds")
    bucket["cost_usd"] = 0.0
    bucket["requests"] = 0
    bucket["input_tokens"] = 0
    bucket["output_tokens"] = 0
    bucket["cache_read_input_tokens"] = 0
    bucket["cache_creation_input_tokens"] = 0
    bucket["blocked_count"] = 0
    bucket["models"] = {}


def get_or_create_user_bucket(label: str) -> dict:
    """Return the per-user bucket, refreshing cap + rolling over period if needed."""
    cur_period = current_user_period_key()
    b = state.quota_stats["by_user"].get(label)
    if b is None:
        b = _new_user_bucket(label)
        state.quota_stats["by_user"][label] = b
        return b
    # Live-refresh cap from env so changes apply without restart.
    b["cap_usd"] = cap_for_label(label)
    b["period"] = settings.USER_QUOTA_PERIOD
    if b.get("period_key") != cur_period:
        _reset_user_bucket(b, cur_period)
    return b


def is_user_over_cap(label: str) -> tuple[bool, float, float]:
    """Return (over, used_usd, cap_usd). cap<=0 means unlimited (never over)."""
    if not settings.USER_QUOTA_ENABLED:
        return False, 0.0, 0.0
    b = get_or_create_user_bucket(label)
    cap = b["cap_usd"]
    used = b["cost_usd"]
    if cap <= 0:
        return False, used, 0.0
    return used >= cap, used, cap


def record_user_usage(label: str, usage: dict, cost: float, model_key: str | None = None) -> None:
    """Accumulate one response's cost/usage into the per-user bucket.

    Runs even when USER_QUOTA_ENABLED=false — we still want the dashboard
    to attribute spend to a user. The cap is only ENFORCED when enabled.

    `model_key` enables per-user × per-model breakdown for the dashboard.
    """
    if not label:
        return
    b = get_or_create_user_bucket(label)
    in_t = usage.get("input_tokens", 0) or 0
    out_t = usage.get("output_tokens", 0) or 0
    cr_t = usage.get("cache_read_input_tokens", 0) or 0
    cw_t = usage.get("cache_creation_input_tokens", 0) or 0
    b["cost_usd"] += cost
    b["requests"] += 1
    b["input_tokens"] += in_t
    b["output_tokens"] += out_t
    b["cache_read_input_tokens"] += cr_t
    b["cache_creation_input_tokens"] += cw_t
    b["last_seen"] = datetime.now().isoformat(timespec="seconds")

    if model_key:
        # Older buckets loaded from v3 .quota.json don't have this dict yet.
        if "models" not in b or not isinstance(b.get("models"), dict):
            b["models"] = {}
        mb = b["models"].setdefault(
            model_key,
            {
                "model": model_key,
                "requests": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "cache_read_input_tokens": 0,
                "cache_creation_input_tokens": 0,
                "cost_usd": 0.0,
            },
        )
        mb["requests"] += 1
        mb["input_tokens"] += in_t
        mb["output_tokens"] += out_t
        mb["cache_read_input_tokens"] += cr_t
        mb["cache_creation_input_tokens"] += cw_t
        mb["cost_usd"] += cost


def _user_bucket_view(b: dict) -> dict:
    """Public-facing shape of a per-user bucket (rounded cost, derived %)."""
    cap = float(b.get("cap_usd") or 0.0)
    used = float(b.get("cost_usd") or 0.0)
    pct = round((used / cap) * 100, 2) if cap > 0 else None
    raw_models = b.get("models") or {}
    models_view = sorted(
        (
            {
                "model": m.get("model", k),
                "requests": m.get("requests", 0),
                "input_tokens": m.get("input_tokens", 0),
                "output_tokens": m.get("output_tokens", 0),
                "cache_read_input_tokens": m.get("cache_read_input_tokens", 0),
                "cache_creation_input_tokens": m.get("cache_creation_input_tokens", 0),
                "cost_usd": round(float(m.get("cost_usd") or 0.0), 6),
            }
            for k, m in raw_models.items()
            if isinstance(m, dict)
        ),
        key=lambda x: x["cost_usd"],
        reverse=True,
    )
    return {
        "label": b.get("label"),
        "cap_usd": round(cap, 4),
        "cost_usd": round(used, 6),
        "cost_pct": pct,
        "over_cap": (cap > 0 and used >= cap),
        "period": b.get("period", settings.USER_QUOTA_PERIOD),
        "period_key": b.get("period_key"),
        "period_start": b.get("period_start"),
        "requests": b.get("requests", 0),
        "input_tokens": b.get("input_tokens", 0),
        "output_tokens": b.get("output_tokens", 0),
        "cache_read_input_tokens": b.get("cache_read_input_tokens", 0),
        "cache_creation_input_tokens": b.get("cache_creation_input_tokens", 0),
        "blocked_count": b.get("blocked_count", 0),
        "models": models_view,
        "first_seen": b.get("first_seen"),
        "last_seen": b.get("last_seen"),
    }
