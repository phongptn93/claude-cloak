"""All mutable runtime state, in one place.

INVARIANT: nothing here is ever rebound by another module. Dicts are mutated in
place; every scalar that the original single-file proxy carried as a ``global``
now lives on the :data:`runtime` singleton, so there is no ``global`` statement
left in the codebase and no module can hold a stale copy.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

import httpx

from .constants import CAPTURE_HEADERS
from .env import env_key, env_str

quota_stats: dict[str, Any] = {
    "rate_limits": {},  # latest anthropic-ratelimit-* headers seen
    "rate_limits_updated_at": None,
    "usage_total": {
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_creation_input_tokens": 0,
        "cache_creation_5m_input_tokens": 0,
        "cache_creation_1h_input_tokens": 0,
        "cache_read_input_tokens": 0,
    },
    "cost_usd_total": 0.0,
    "by_model": {},  # model_key -> {usage..., cost_usd, requests}
    "by_session": {},  # session_id -> {requests, tokens, cost_usd, first_seen, last_seen}
    "by_day": {},  # YYYY-MM-DD -> {requests, tokens, cost_usd}
    "by_day_user": {},  # YYYY-MM-DD -> {user_label -> {requests, tokens, cost_usd}}
    "by_user": {},  # label -> {cap_usd, period_key, cost_usd, requests, tokens, blocked_count, models, ...}
    "messages_requests": 0,
    "last_request_at": None,
    "period_month": "",  # YYYY-MM of current tracking period; auto-reset on rollover
    "unpriced_models": {},  # raw model id -> count (costed at PRICING_FALLBACK)
}

stream_stats: dict[str, Any] = {
    "streams_started": 0,
    "streams_completed": 0,
    "stalls": 0,  # upstream went silent past UPSTREAM_STALL_SECONDS
    "client_disconnects": 0,  # client went away mid-stream (usually benign)
    "connect_retries": 0,  # transport retried before any byte was forwarded
    "pool_waits": 0,  # request waited on a free upstream connection
    "pool_wait_ms_total": 0,
    "ttfb_ms_total": 0,  # time-to-first-byte, summed over streams
    "ttfb_ms_max": 0,
    "ttfb_samples": 0,
    "last_stall_at": None,
}

coach_stats: dict[str, Any] = {
    "tools": {},  # tool_name -> count (assistant tool_use blocks)
    "tool_results_seen": 0,  # tool_result blocks observed in user turns
    "tool_errors": 0,  # of those, is_error == true
    "assistant_turns": 0,  # /v1/messages responses processed
    "stop_reasons": {},  # stop_reason -> count
    "by_hour": {},  # "0".."23" -> assistant_turns (local time)
    "first_seen": None,
    "last_seen": None,
}

token_saver_stats: dict[str, Any] = {
    "requests_optimized": 0,
    "cache_breakpoints_added": 0,
    "cache_breakpoints_skipped_full": 0,
    "tool_results_truncated": 0,
    "bytes_saved": 0,
    "tokens_saved_est": 0,
    "beta_runtime_disabled": False,
}

# Buffer of (ts_ns: str, labels: dict, fields: dict). Single-process,
# single-event-loop FastAPI => no lock needed (list ops are atomic in CPython).
loki_buffer: list[tuple[str, dict, dict]] = []

# ip -> [failure_count, first_failure_monotonic]
admin_failures: dict[str, list] = {}

# Captured device fingerprint, seeded from CAPTURED_* keys in .env.
captured_identity: dict[str, str] = {}
for _header in CAPTURE_HEADERS:
    _value = env_str(env_key(_header))
    if _value:
        captured_identity[_header] = _value

# Header names seen on the wire that no policy covers yet (warn once each).
warned_unknown_headers: set[str] = set()


@dataclass
class Runtime:
    """Process-lifetime scalars. Mutated via ``runtime.<field> = ...``."""

    identity_captured: bool = False
    captured_at: str = ""

    request_count: int = 0
    blocked_requests_count: int = 0
    sanitized_bodies_count: int = 0

    # Latched True when upstream rejects the extended-cache-ttl beta header.
    cache_ttl_runtime_disabled: bool = False

    last_quota_save_at: float = 0.0
    last_coach_save_at: float = 0.0

    loki_dropped_count: int = 0
    loki_last_warn_at: float = 0.0
    loki_flusher_task: asyncio.Task | None = None

    http_client: httpx.AsyncClient | None = None
    telemetry_client: httpx.AsyncClient | None = None

    extra: dict[str, Any] = field(default_factory=dict)


runtime = Runtime(
    identity_captured=bool(captured_identity),
    captured_at=env_str("CAPTURED_AT"),
)
