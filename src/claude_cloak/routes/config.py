"""Config console API: data, login, logout, apply."""

from __future__ import annotations

import hmac

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from .. import settings, state
from ..admin import (
    _admin_lockout_remaining,
    _issue_admin_cookie,
    _record_admin_failure,
    _request_is_admin,
)
from ..config_console import _config_apply, _config_view
from ..terminal import BG_GREEN, BG_RED, BOLD, GREEN, RED, RESET, log

router = APIRouter()


@router.get("/config/data")
async def config_data(request: Request):
    return _config_view(_request_is_admin(request))


@router.post("/config/login")
async def config_login(request: Request):
    """Exchange ADMIN_TOKEN for a short-lived signed cookie."""
    client_ip = getattr(request.state, "client_ip", "") or ""
    if not settings.ADMIN_TOKEN:
        return JSONResponse(
            {
                "ok": False,
                "error": "ADMIN_TOKEN is not set — the console is read-only. "
                "Add ADMIN_TOKEN to .env and restart to enable editing.",
            },
            status_code=503,
        )

    locked_for = _admin_lockout_remaining(client_ip)
    if locked_for:
        return JSONResponse(
            {"ok": False, "error": f"too many failed attempts — retry in {locked_for}s"},
            status_code=429,
        )

    try:
        payload = await request.json()
    except Exception:
        payload = {}
    supplied = str(payload.get("token") or "")

    # Constant-time compare so a wrong token cannot be recovered by timing.
    if not hmac.compare_digest(supplied, settings.ADMIN_TOKEN):
        _record_admin_failure(client_ip)
        left = max(0, settings.ADMIN_MAX_FAILED - state.admin_failures.get(client_ip, [0])[0])
        log(
            f"  {BG_RED}{BOLD} CONFIG {RESET} {RED}failed login from {client_ip or '<unknown>'}{RESET}"
        )
        return JSONResponse(
            {"ok": False, "error": f"invalid token ({left} attempt(s) left)"},
            status_code=401,
        )

    state.admin_failures.pop(client_ip, None)
    cookie, expires_at = _issue_admin_cookie()
    resp = JSONResponse({"ok": True, "expires_at": expires_at})
    resp.set_cookie(
        settings.ADMIN_COOKIE_NAME,
        cookie,
        max_age=int(settings.ADMIN_SESSION_HOURS * 3600),
        httponly=True,  # not readable from JS, so XSS cannot lift it
        samesite="strict",  # no cross-site form can ride the session
        path="/",
    )
    log(
        f"  {BG_GREEN}{BOLD} CONFIG {RESET} {GREEN}admin signed in from {client_ip or '<unknown>'}{RESET}"
    )
    return resp


@router.post("/config/logout")
async def config_logout():
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(settings.ADMIN_COOKIE_NAME, path="/")
    return resp


@router.post("/config/apply")
async def config_apply(request: Request):
    """Write a batch of settings. Requires a valid admin session."""
    if not _request_is_admin(request):
        return JSONResponse(
            {
                "ok": False,
                "error": "not authenticated"
                if settings.ADMIN_TOKEN
                else "ADMIN_TOKEN is not set — editing is disabled",
            },
            status_code=401,
        )
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    changes = payload.get("changes")
    if not isinstance(changes, dict) or not changes:
        return JSONResponse({"ok": False, "error": "no changes supplied"}, status_code=400)

    result = _config_apply(changes)
    result["ok"] = not result["rejected"]
    return JSONResponse(result, status_code=200 if result["ok"] else 207)
