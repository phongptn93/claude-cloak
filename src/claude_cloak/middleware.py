"""Raw ASGI access control: IP whitelist, admin gate, stats privacy, spend caps."""

from __future__ import annotations

from fastapi.responses import JSONResponse

from . import settings
from .access import (
    is_ip_allowed,
    label_for_ip,
    parse_key_prefix,
    parse_user_prefix,
    resolve_client_ip,
    seconds_until_user_period_reset,
)
from .proxy_keys import record_use, verify_secret
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
    - In server mode every request must come from an IP inside ALLOWED_IPS,
      or carry a valid proxy key (``/k/<key>/...`` or PROXY_KEY_HEADER) —
      the door for clients whose address is dynamic.
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

        # ── Proxy key ──────────────────────────────────────────────────
        # Presented either as the first URL segment (/k/<key>/v1/messages)
        # or as PROXY_KEY_HEADER. A key identifies the user AND admits them
        # from any address; it never opens /admin or /config, which stay
        # ADMIN_IPS-only.
        url_key, path_after_key = parse_key_prefix(raw_path)
        key_record = None
        if url_key is not None and not settings.PROXY_KEYS_ENABLED:
            # Refuse rather than forward: a path shaped like a key attempt is
            # not an upstream path, and answering 404 from Anthropic would
            # read as "wrong key" instead of "this proxy has keys turned off".
            log(
                f"  {BG_RED}{BOLD} 403 {RESET} {RED}proxy key presented but "
                f"PROXY_KEYS_ENABLED=false → {method} /{settings.PROXY_KEY_URL_SEGMENT}/…{RESET}"
            )
            await JSONResponse(
                {"error": "forbidden", "reason": "proxy key authentication is disabled"},
                status_code=403,
            )(scope, receive, send)
            return
        if settings.PROXY_KEYS_ENABLED:
            presented = url_key or _header_value(scope, settings.PROXY_KEY_HEADER)
            if presented:
                key_record, reason = verify_secret(presented)
                if key_record is None:
                    log(
                        f"  {BG_RED}{BOLD} 403 {RESET} {RED}proxy key {reason}: "
                        f"{_mask_key(presented)} from {client_ip or '<unknown>'} → "
                        f"{method} (key path hidden){RESET}"
                    )
                    await JSONResponse(
                        {"error": "forbidden", "reason": f"proxy key {reason}"},
                        status_code=403,
                    )(scope, receive, send)
                    return
            if url_key is not None:
                # Rewrite the path before anything else reads it: routing, the
                # logs and the upstream URL must never carry the secret.
                scope["path"] = path_after_key
                if scope.get("raw_path"):
                    scope["raw_path"] = path_after_key.encode("latin-1")
                raw_path = path_after_key

        url_label, stripped_path = parse_user_prefix(raw_path)
        # A key names its own user, so a whitelisted client cannot bill its
        # traffic to someone else's bucket by also passing /u/<label>/.
        user_label = (key_record or {}).get("label") or url_label or label_for_ip(client_ip)

        # Stash in scope.state so the downstream handler can read via
        # request.state.<attr> — Starlette's Request.state is a thin wrapper
        # around scope["state"] (a plain dict).
        scope.setdefault("state", {})
        state = scope["state"]
        state["client_ip"] = client_ip
        state["url_user_label"] = url_label
        state["stripped_path"] = stripped_path
        state["user_label"] = user_label
        state["proxy_key_id"] = key_record["id"] if key_record else None

        # Admin + config + key-management endpoints are gated SOLELY by
        # ADMIN_IPS (default loopback). /config and /keys carry a second,
        # stronger gate of their own (ADMIN_TOKEN) — this one only narrows
        # where a login can be attempted from. A proxy key buys nothing here:
        # it admits its holder to the proxy, not to its administration.
        # We check before the general whitelist so the VM operator can curl
        # /admin/* from 127.0.0.1 / ::1 without also having to add loopback
        # to ALLOWED_IPS — those two lists are meant to be independent.
        if (
            raw_path.startswith("/admin/")
            or raw_path in ("/config", "/keys")
            or raw_path.startswith("/config/")
            or raw_path.startswith("/keys/")
        ):
            if client_ip not in settings.ADMIN_IPS:
                await JSONResponse({"error": "forbidden"}, status_code=403)(scope, receive, send)
                return
        else:
            # IP whitelist — applies to every non-admin path in server mode
            # (dashboard, /quota, /v1/*, /u/<label>/* and so on), unless the
            # caller presented a key and keys are allowed to stand in for it.
            keyed_in = key_record is not None and settings.PROXY_KEY_BYPASS_IP_ALLOWLIST
            if settings.DEPLOY_MODE == "server" and not keyed_in and not is_ip_allowed(client_ip):
                log(
                    f"  {BG_RED}{BOLD} 403 {RESET} {RED}IP not allowed: "
                    f"{client_ip or '<unknown>'} → {method} {raw_path}{RESET}"
                )
                await JSONResponse({"error": "forbidden"}, status_code=403)(scope, receive, send)
                return

        if key_record is not None:
            record_use(key_record, client_ip)

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


def _header_value(scope, name: str) -> str:
    """Read one request header out of a raw ASGI scope."""
    wanted = name.encode("latin-1")
    for raw_key, raw_val in scope.get("headers", []):
        if raw_key == wanted:
            return raw_val.decode("latin-1").strip()
    return ""


def _mask_key(secret: str) -> str:
    """Enough of a rejected key to correlate two attempts, never enough to use."""
    return (secret[:4] + "…") if len(secret) > 4 else "…"
