"""Raw ASGI access control: IP whitelist, admin gate, stats privacy, spend caps."""

from __future__ import annotations

from fastapi.responses import JSONResponse

from . import settings
from .access import (
    is_ip_allowed,
    label_for_ip,
    parse_user_prefix,
    resolve_client_ip,
    seconds_until_user_period_reset,
)
from .quota.users import get_or_create_user_bucket, is_user_over_cap
from .sanitize import is_blocked_path
from .terminal import BG_RED, BG_YELLOW, BOLD, RED, RESET, YELLOW, log


class AccessControlMiddleware:
    """Server-mode access gate: IP whitelist + per-user spend cap.

    Implemented as a pure ASGI middleware (not @router.middleware("http"))
    because Starlette's BaseHTTPMiddleware wraps streaming responses in a
    TaskGroup and surfaces benign client disconnects as
    "ExceptionGroup: unhandled errors in a TaskGroup" — noisy and confusing
    when half our traffic is SSE-streamed /v1/messages responses.

    - In local mode this is a no-op (preserves the original single-machine UX).
    - In server mode every request must come from an IP inside ALLOWED_IPS.
    - When USER_QUOTA_ENABLED, /v1/ requests from a user that exceeded their
      cap are short-circuited with HTTP 429 (plus Retry-After).
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        client = scope.get("client")
        peer_ip = client[0] if client else ""
        # Behind a configured reverse proxy the peer is the proxy; every gate
        # below must judge the real client instead. Untrusted peers keep their
        # own address, so a forged header buys nothing.
        forwarded_for = ""
        if settings.TRUSTED_PROXY_NETWORKS:
            for raw_key, raw_val in scope.get("headers", []):
                if raw_key == b"x-forwarded-for":
                    forwarded_for = raw_val.decode("latin-1")
                    break
        client_ip = resolve_client_ip(peer_ip, forwarded_for)
        raw_path = scope.get("path") or "/"
        method = scope.get("method", "GET")

        url_label, stripped_path = parse_user_prefix(raw_path)
        user_label = url_label or label_for_ip(client_ip)

        # Stash in scope.state so the downstream handler can read via
        # request.state.<attr> — Starlette's Request.state is a thin wrapper
        # around scope["state"] (a plain dict).
        scope.setdefault("state", {})
        state = scope["state"]
        state["client_ip"] = client_ip
        state["url_user_label"] = url_label
        state["stripped_path"] = stripped_path
        state["user_label"] = user_label

        # Admin + config endpoints are gated SOLELY by ADMIN_IPS (default
        # loopback). /config carries a second, stronger gate of its own
        # (ADMIN_TOKEN) — this one only narrows where a login can be
        # attempted from. We
        # check before the general whitelist so the VM operator can curl
        # /admin/* from 127.0.0.1 / ::1 without also having to add loopback
        # to ALLOWED_IPS — those two lists are meant to be independent.
        if (
            raw_path.startswith("/admin/")
            or raw_path == "/config"
            or raw_path.startswith("/config/")
        ):
            if client_ip not in settings.ADMIN_IPS:
                await JSONResponse({"error": "forbidden"}, status_code=403)(scope, receive, send)
                return
        else:
            # IP whitelist — applies to every non-admin path in server mode
            # (dashboard, /quota, /v1/*, /u/<label>/* and so on).
            if settings.DEPLOY_MODE == "server" and not is_ip_allowed(client_ip):
                log(
                    f"  {BG_RED}{BOLD} 403 {RESET} {RED}IP not allowed: "
                    f"{client_ip or '<unknown>'} → {method} {raw_path}{RESET}"
                )
                await JSONResponse({"error": "forbidden"}, status_code=403)(scope, receive, send)
                return

        # Stats endpoints — gate to STATS_VIEW_IPS when STATS_PRIVATE is enabled.
        if settings.STATS_PRIVATE:
            is_stats = raw_path in (
                "/health",
                "/quota",
                "/quota/users",
                "/dashboard",
                "/coach",
            ) or raw_path.startswith("/quota/users/")
            if is_stats and client_ip not in settings.STATS_VIEW_IPS:
                await JSONResponse({"error": "forbidden"}, status_code=403)(scope, receive, send)
                return

        # Per-user spend cap — only meaningful for upstream API calls. Use the
        # URL-stripped path so /u/phong/v1/messages is treated as /v1/messages.
        if (
            settings.USER_QUOTA_ENABLED
            and settings.USER_QUOTA_HARD_LIMIT
            and stripped_path.startswith("/v1/")
            and not is_blocked_path(stripped_path.lstrip("/"))
        ):
            over, used, cap = is_user_over_cap(user_label)
            if over:
                bucket = get_or_create_user_bucket(user_label)
                bucket["blocked_count"] += 1
                retry = seconds_until_user_period_reset()
                log(
                    f"  {BG_YELLOW}{BOLD} 429 {RESET} {YELLOW}user '{user_label}' over cap "
                    f"${used:.2f}/${cap:.2f} (period={settings.USER_QUOTA_PERIOD}, reset in {retry}s){RESET}"
                )
                await JSONResponse(
                    {
                        "type": "error",
                        "error": {
                            "type": "user_quota_exceeded",
                            "message": (
                                f"User '{user_label}' exceeded {settings.USER_QUOTA_PERIOD} cap "
                                f"${cap:.2f} (used ${used:.4f}). Resets at next period boundary."
                            ),
                        },
                    },
                    status_code=429,
                    headers={"Retry-After": str(retry)},
                )(scope, receive, send)
                return

        await self.app(scope, receive, send)
