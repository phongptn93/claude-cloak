"""Outbound header construction, response filtering, stream health view."""

from __future__ import annotations

import secrets

import httpx
from fastapi import Request

from . import settings, state
from .constants import EXCLUDED_REQUEST_HEADERS, STRIP_REQUEST_HEADERS, STRIP_RESPONSE_HEADERS


def build_request_headers(request: Request) -> dict[str, str]:
    headers = {}

    for k, v in request.headers.items():
        kl = k.lower()

        # Skip excluded headers
        if kl in EXCLUDED_REQUEST_HEADERS:
            continue

        # Strip IP-leaking headers
        if kl in STRIP_REQUEST_HEADERS:
            continue

        # Strip cookies to prevent cross-device tracking
        if kl == "cookie":
            continue

        headers[k] = v

    # Override identity headers với giá trị đã lock
    if state.captured_identity:
        for k in list(headers.keys()):
            kl = k.lower()
            if kl in state.captured_identity:
                headers[k] = state.captured_identity[kl]

        # Add any captured headers that aren't in the request
        # (ensures consistent fingerprint even if client omits some)
        existing_lower = {k.lower() for k in headers}
        for h, v in state.captured_identity.items():
            if h not in existing_lower:
                headers[h] = v

    # Replace x-request-id with a fresh random UUID to avoid
    # leaking per-device identifiers while keeping each request unique
    for k in list(headers.keys()):
        if k.lower() == "x-request-id":
            headers[k] = secrets.token_hex(16)
            break

    return headers


def filter_response_headers(response: httpx.Response) -> dict[str, str]:
    return {k: v for k, v in response.headers.items() if k.lower() not in STRIP_RESPONSE_HEADERS}


def _stream_health_view() -> dict:
    """Derived view of stream_stats for /health, /quota and the dashboard.

    `stall_rate` and the TTFB figures are what to look at when users report
    a response stalling mid-stream: a non-zero stall count points at the
    upstream connection, while a high average TTFB with pool waits points at
    the proxy's own connection pool being too small for the traffic.
    """
    started = state.stream_stats["streams_started"]
    samples = state.stream_stats["ttfb_samples"]
    waits = state.stream_stats["pool_waits"]
    return {
        "streams_started": started,
        "streams_completed": state.stream_stats["streams_completed"],
        "stalls": state.stream_stats["stalls"],
        "stall_rate": round(state.stream_stats["stalls"] / started, 4) if started else 0.0,
        "last_stall_at": state.stream_stats["last_stall_at"],
        "client_disconnects": state.stream_stats["client_disconnects"],
        "connect_retries": state.stream_stats["connect_retries"],
        "pool_waits": waits,
        "pool_wait_ms_avg": round(state.stream_stats["pool_wait_ms_total"] / waits) if waits else 0,
        "ttfb_ms_avg": round(state.stream_stats["ttfb_ms_total"] / samples) if samples else 0,
        "ttfb_ms_max": state.stream_stats["ttfb_ms_max"],
        "config": {
            "stall_seconds": settings.UPSTREAM_STALL_SECONDS,
            "max_connections": settings.UPSTREAM_MAX_CONNECTIONS,
            "pool_timeout": settings.UPSTREAM_POOL_TIMEOUT,
            "read_timeout": settings.UPSTREAM_READ_TIMEOUT,
            "connect_retries": settings.UPSTREAM_CONNECT_RETRIES,
        },
    }
