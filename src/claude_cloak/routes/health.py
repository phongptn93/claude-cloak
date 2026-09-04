"""GET /health."""

from __future__ import annotations

from fastapi import APIRouter

from .. import settings, state
from ..constants import STRIP_REQUEST_HEADERS
from ..tls import certificate_view
from ..upstream import _stream_health_view

router = APIRouter()


@router.get("/health")
async def health():
    return {
        "status": "ok",
        "identity_captured": state.runtime.identity_captured,
        "headers_locked": len(state.captured_identity),
        "telemetry_blocked": state.runtime.blocked_requests_count,
        "bodies_sanitized": state.runtime.sanitized_bodies_count,
        "ip_headers_stripped": len(STRIP_REQUEST_HEADERS),
        "unknown_headers_seen": sorted(state.warned_unknown_headers),
        "token_saver": {
            "enabled": settings.TOKEN_SAVER_ENABLED,
            "cache_extend_ttl_configured": settings.CACHE_EXTEND_TTL,
            "cache_extend_ttl_active": (
                settings.CACHE_EXTEND_TTL and not state.runtime.cache_ttl_runtime_disabled
            ),
            "tool_result_truncate": settings.TOOL_RESULT_TRUNCATE,
            "tool_result_max_bytes": settings.TOOL_RESULT_MAX_BYTES,
            **state.token_saver_stats,
        },
        "quota": {
            "enabled": settings.QUOTA_TRACKING_ENABLED,
            "messages_requests": state.quota_stats["messages_requests"],
            "last_request_at": state.quota_stats["last_request_at"],
            "rate_limits": state.quota_stats["rate_limits"],
            "rate_limits_updated_at": state.quota_stats["rate_limits_updated_at"],
            "usage_total": state.quota_stats["usage_total"],
            "cost_usd_total": round(state.quota_stats["cost_usd_total"], 6),
            "by_model": [
                {**v, "cost_usd": round(v["cost_usd"], 6)}
                for v in state.quota_stats["by_model"].values()
            ],
            "by_session_count": len(state.quota_stats["by_session"]),
            "by_day_count": len(state.quota_stats["by_day"]),
            "by_user_count": len(state.quota_stats["by_user"]),
            "unpriced_models": state.quota_stats["unpriced_models"],
        },
        "stream": _stream_health_view(),
        "tls": certificate_view(),
        "deploy": {
            "mode": settings.DEPLOY_MODE,
            "bind_host": settings.LOCAL_HOST,
            "allowed_ips": [str(n) for n in settings.ALLOWED_NETWORKS],
            "labels_configured": len(settings.IP_LABEL_MAP),
            "user_quota_enabled": settings.USER_QUOTA_ENABLED,
            "user_quota_period": settings.USER_QUOTA_PERIOD,
        },
    }
