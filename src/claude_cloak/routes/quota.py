"""Quota + per-user endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from .. import settings, state
from ..access import seconds_until_user_period_reset
from ..quota.users import _user_bucket_view, get_or_create_user_bucket
from ..upstream import _stream_health_view

router = APIRouter()


@router.get("/quota")
async def quota():
    """Compact quota summary tuned for human display."""
    rl = state.quota_stats["rate_limits"]

    sessions = sorted(
        state.quota_stats["by_session"].values(),
        key=lambda s: s.get("last_seen", ""),
        reverse=True,
    )

    days = sorted(
        state.quota_stats["by_day"].values(),
        key=lambda d: d.get("date", ""),
        reverse=True,
    )[:15]

    summary = {
        "cost_usd_total": round(state.quota_stats["cost_usd_total"], 4),
        "messages_requests": state.quota_stats["messages_requests"],
        "tokens": state.quota_stats["usage_total"],
        "by_model": [
            {
                "model": v["model"],
                "requests": v["requests"],
                "input_tokens": v["input_tokens"],
                "output_tokens": v["output_tokens"],
                "cache_read_input_tokens": v["cache_read_input_tokens"],
                "cache_creation_input_tokens": v["cache_creation_input_tokens"],
                "cost_usd": round(v["cost_usd"], 4),
                # Users that touched this model (aggregated from by_user[*].models).
                "users": sorted(
                    (
                        {
                            "user_label": ub.get("label"),
                            "requests": (ub.get("models", {}).get(v["model"], {}) or {}).get(
                                "requests", 0
                            ),
                            "input_tokens": (ub.get("models", {}).get(v["model"], {}) or {}).get(
                                "input_tokens", 0
                            ),
                            "output_tokens": (ub.get("models", {}).get(v["model"], {}) or {}).get(
                                "output_tokens", 0
                            ),
                            "cost_usd": round(
                                (ub.get("models", {}).get(v["model"], {}) or {}).get(
                                    "cost_usd", 0.0
                                ),
                                4,
                            ),
                        }
                        for ub in state.quota_stats["by_user"].values()
                        if isinstance(ub.get("models"), dict) and v["model"] in ub["models"]
                    ),
                    key=lambda x: x["cost_usd"],
                    reverse=True,
                ),
            }
            for v in state.quota_stats["by_model"].values()
        ],
        "by_session": [
            {
                "session_id": s["session_id"],
                "user_label": s.get("user_label", ""),
                "requests": s["requests"],
                "input_tokens": s["input_tokens"],
                "output_tokens": s["output_tokens"],
                "cache_read_input_tokens": s["cache_read_input_tokens"],
                "cache_creation_input_tokens": s["cache_creation_input_tokens"],
                "cost_usd": round(s["cost_usd"], 4),
                "models": s.get("models", {}),
                "first_seen": s.get("first_seen"),
                "last_seen": s.get("last_seen"),
            }
            for s in sessions
        ],
        "by_day": [
            {
                "date": d["date"],
                "requests": d["requests"],
                "input_tokens": d["input_tokens"],
                "output_tokens": d["output_tokens"],
                "cache_read_input_tokens": d["cache_read_input_tokens"],
                "cache_creation_input_tokens": d["cache_creation_input_tokens"],
                "cost_usd": round(d["cost_usd"], 4),
                # Top users contributing to this date (sorted by cost desc).
                "users": sorted(
                    (
                        {
                            "user_label": u["user_label"],
                            "requests": u["requests"],
                            "input_tokens": u["input_tokens"],
                            "output_tokens": u["output_tokens"],
                            "cache_read_input_tokens": u["cache_read_input_tokens"],
                            "cache_creation_input_tokens": u["cache_creation_input_tokens"],
                            "cost_usd": round(u["cost_usd"], 4),
                        }
                        for u in (
                            state.quota_stats["by_day_user"].get(d["date"], {}) or {}
                        ).values()
                    ),
                    key=lambda x: x["cost_usd"],
                    reverse=True,
                ),
            }
            for d in days
        ],
        "period_month": state.quota_stats["period_month"],
        "monthly_reset_enabled": settings.QUOTA_MONTHLY_RESET,
        "deploy_mode": settings.DEPLOY_MODE,
        "stream": _stream_health_view(),
        # Models with no published price in PRICING — their cost is an
        # estimate at the PRICING_FALLBACK rate, not the real invoice.
        "unpriced_models": state.quota_stats["unpriced_models"],
        # `users` is always populated when at least one labelled request has
        # been recorded, even with USER_QUOTA_ENABLED=false — that way the
        # dashboard can attribute spend to users regardless of cap config.
        # `cap_enforced` lets the UI decide whether to show cap progress bars.
        "user_quota": {
            "enabled": settings.USER_QUOTA_ENABLED,
            "cap_enforced": settings.USER_QUOTA_ENABLED and settings.USER_QUOTA_HARD_LIMIT,
            "period": settings.USER_QUOTA_PERIOD,
            "hard_limit": settings.USER_QUOTA_HARD_LIMIT,
            "default_cap_usd": settings.USER_QUOTA_DEFAULT_USD,
            "reset_in_seconds": seconds_until_user_period_reset()
            if settings.USER_QUOTA_ENABLED
            else None,
            "users": sorted(
                (_user_bucket_view(b) for b in state.quota_stats["by_user"].values()),
                key=lambda u: u.get("cost_usd") or 0.0,
                reverse=True,
            ),
        },
        "rate_limits": {
            "requests_remaining": rl.get("requests-remaining"),
            "requests_limit": rl.get("requests-limit"),
            "requests_reset": rl.get("requests-reset"),
            "input_tokens_remaining": rl.get("input-tokens-remaining"),
            "input_tokens_limit": rl.get("input-tokens-limit"),
            "input_tokens_reset": rl.get("input-tokens-reset"),
            "output_tokens_remaining": rl.get("output-tokens-remaining"),
            "output_tokens_limit": rl.get("output-tokens-limit"),
            "output_tokens_reset": rl.get("output-tokens-reset"),
            "tokens_remaining": rl.get("tokens-remaining"),
            "tokens_limit": rl.get("tokens-limit"),
            "tokens_reset": rl.get("tokens-reset"),
            "retry_after": rl.get("retry-after"),
            "updated_at": state.quota_stats["rate_limits_updated_at"],
        },
    }
    return summary


@router.get("/quota/users")
async def quota_users():
    """List every per-user bucket with cap usage."""
    # Refresh period roll-over on labels we already know about.
    for label in list(state.quota_stats["by_user"].keys()):
        get_or_create_user_bucket(label)
    users = sorted(
        (_user_bucket_view(b) for b in state.quota_stats["by_user"].values()),
        key=lambda u: u.get("cost_usd") or 0.0,
        reverse=True,
    )
    return {
        "enabled": settings.USER_QUOTA_ENABLED,
        "period": settings.USER_QUOTA_PERIOD,
        "hard_limit": settings.USER_QUOTA_HARD_LIMIT,
        "default_cap_usd": settings.USER_QUOTA_DEFAULT_USD,
        "reset_in_seconds": seconds_until_user_period_reset()
        if settings.USER_QUOTA_ENABLED
        else None,
        "users": users,
    }


@router.get("/quota/users/{label}")
async def quota_user(label: str):
    b = state.quota_stats["by_user"].get(label)
    if b is None:
        raise HTTPException(status_code=404, detail="user not found")
    get_or_create_user_bucket(label)  # period roll-over check
    return _user_bucket_view(b)


@router.get("/u/{label}/whoami")
async def whoami(label: str):
    """Client setup verification: returns the bucket for the URL-prefix label.

    Hitting GET http://vm:9999/u/phong/whoami from a whitelisted client
    confirms (a) the IP is allowed, (b) the label is parsed correctly,
    (c) the cap is what the operator configured.
    """
    if not settings.USER_LABEL_RE.match(label):
        raise HTTPException(status_code=400, detail="invalid label")
    b = get_or_create_user_bucket(label) if settings.USER_QUOTA_ENABLED else None
    return {
        "label": label,
        "user_quota_enabled": settings.USER_QUOTA_ENABLED,
        "bucket": _user_bucket_view(b) if b else None,
    }
