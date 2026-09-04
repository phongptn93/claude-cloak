"""Admin cookie issuing/verification and per-IP login lockout."""

from __future__ import annotations

import hashlib
import hmac
import time

from fastapi import Request

from . import settings, state


def _issue_admin_cookie() -> tuple[str, int]:
    """Mint a signed, expiring admin cookie value.

    The signature is HMAC-SHA256 over the expiry using SESSION_SECRET, so no
    server-side session store is needed and a restart that regenerates the
    secret invalidates every outstanding cookie.
    """
    expires_at = int(time.time() + settings.ADMIN_SESSION_HOURS * 3600)
    sig = hmac.new(
        settings.SESSION_SECRET.encode(), str(expires_at).encode(), hashlib.sha256
    ).hexdigest()
    return f"{expires_at}.{sig}", expires_at


def _verify_admin_cookie(raw: str | None) -> bool:
    if not raw or "." not in raw:
        return False
    expires_str, _, sig = raw.partition(".")
    try:
        expires_at = int(expires_str)
    except ValueError:
        return False
    if expires_at <= time.time():
        return False
    expected = hmac.new(
        settings.SESSION_SECRET.encode(), expires_str.encode(), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, sig)


def _admin_lockout_remaining(ip: str) -> int:
    """Seconds left on a brute-force lockout for this IP (0 = not locked)."""
    entry = state.admin_failures.get(ip)
    if not entry or entry[0] < settings.ADMIN_MAX_FAILED:
        return 0
    remaining = settings.ADMIN_LOCKOUT_SECONDS - (time.monotonic() - entry[1])
    if remaining <= 0:
        state.admin_failures.pop(ip, None)
        return 0
    return int(remaining) + 1


def _record_admin_failure(ip: str) -> None:
    entry = state.admin_failures.get(ip)
    if not entry or time.monotonic() - entry[1] > settings.ADMIN_LOCKOUT_SECONDS:
        state.admin_failures[ip] = [1, time.monotonic()]
    else:
        entry[0] += 1


def _request_is_admin(request: Request) -> bool:
    """True when the caller proved possession of ADMIN_TOKEN.

    With no ADMIN_TOKEN configured nobody is an authenticated admin — the
    console stays readable (it is already behind ADMIN_IPS) but every write
    is refused, so an unconfigured deployment cannot be mutated remotely.
    """
    if not settings.ADMIN_TOKEN:
        return False
    return _verify_admin_cookie(request.cookies.get(settings.ADMIN_COOKIE_NAME))
