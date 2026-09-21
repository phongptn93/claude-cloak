"""Proxy-key console: the page, its data, and the issue/revoke API.

Reaching any of this already requires an IP in ADMIN_IPS (enforced in the
access middleware). Every mutation additionally requires a signed-in admin,
because issuing a key hands out access to the proxy — the same bar
``/config/apply`` sets for editing settings, and for the same reason.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse

from .. import proxy_keys, settings, state
from ..access import cap_for_label
from ..admin import _request_is_admin
from ..env import ENV_PATH
from ..terminal import BG_GREEN, BOLD, GREEN, RESET, log
from ..web import keys_html

router = APIRouter()


def _forbidden_if_not_admin(request: Request) -> JSONResponse | None:
    if _request_is_admin(request):
        return None
    return JSONResponse(
        {
            "ok": False,
            "error": "not authenticated"
            if settings.ADMIN_TOKEN
            else "ADMIN_TOKEN is not set — key management is disabled",
        },
        status_code=401,
    )


async def _json_body(request: Request) -> dict:
    try:
        payload = await request.json()
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _spend_for(label: str) -> dict:
    """What this label has spent in the current period, for the key table."""
    bucket = state.quota_stats["by_user"].get(label) or {}
    cap = float(bucket.get("cap_usd") or cap_for_label(label) or 0.0)
    used = float(bucket.get("cost_usd") or 0.0)
    return {
        "label": label,
        "cap_usd": round(cap, 4),
        "cost_usd": round(used, 6),
        "cost_pct": round((used / cap) * 100, 1) if cap > 0 else None,
        "requests": bucket.get("requests", 0),
        "last_seen": bucket.get("last_seen") or "",
    }


@router.get("/keys", response_class=HTMLResponse)
async def keys_page():
    """Key management console. Reachable only from ADMIN_IPS (enforced upstream)."""
    return HTMLResponse(content=keys_html())


@router.get("/keys/data")
async def keys_data(request: Request):
    """Everything the page renders. Secrets are not here — only digests are
    stored at all, and not even those are sent."""
    authenticated = _request_is_admin(request)
    keys = proxy_keys.list_keys()
    labels = sorted(
        {k["label"] for k in keys}
        | set(state.quota_stats["by_user"])
        | set(settings.IP_LABEL_MAP.values())
        | set(settings.USER_QUOTA_CAPS)
    )
    return {
        "authenticated": authenticated,
        "auth_configured": bool(settings.ADMIN_TOKEN),
        "editable": authenticated,
        "keys_enabled": settings.PROXY_KEYS_ENABLED,
        "bypass_ip_allowlist": settings.PROXY_KEY_BYPASS_IP_ALLOWLIST,
        "url_segment": settings.PROXY_KEY_URL_SEGMENT,
        "header_name": settings.PROXY_KEY_HEADER,
        "deploy_mode": settings.DEPLOY_MODE,
        "allowed_ip_count": len(settings.ALLOWED_NETWORKS),
        "user_quota_enabled": settings.USER_QUOTA_ENABLED,
        "quota_period": settings.USER_QUOTA_PERIOD,
        "env_path": ENV_PATH,
        "keys_path": settings.PROXY_KEYS_PATH,
        "known_labels": labels,
        "keys": keys,
        "users": [_spend_for(label) for label in sorted({k["label"] for k in keys})],
    }


@router.post("/keys/create")
async def keys_create(request: Request):
    """Issue a key. The plaintext is in this response and nowhere else, ever."""
    denied = _forbidden_if_not_admin(request)
    if denied is not None:
        return denied
    payload = await _json_body(request)
    try:
        secret, record = proxy_keys.create_key(
            label=str(payload.get("label") or ""),
            note=str(payload.get("note") or ""),
            expires_in_days=payload.get("expires_in_days") or 0,
            created_ip=getattr(request.state, "client_ip", "") or "",
        )
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

    log(
        f"  {BG_GREEN}{BOLD} KEY {RESET} {GREEN}issued for '{record['label']}' "
        f"(id={record['id']}, prefix={record['prefix']}…){RESET}"
    )
    return {
        "ok": True,
        "secret": secret,
        "url_segment": settings.PROXY_KEY_URL_SEGMENT,
        "key": proxy_keys.public_view(record),
    }


@router.post("/keys/update")
async def keys_update(request: Request):
    """Enable, disable, relabel, re-note or re-date one key."""
    denied = _forbidden_if_not_admin(request)
    if denied is not None:
        return denied
    payload = await _json_body(request)
    key_id = str(payload.get("id") or "")
    try:
        record = proxy_keys.update_key(
            key_id,
            enabled=payload.get("enabled") if "enabled" in payload else None,
            note=payload.get("note") if "note" in payload else None,
            label=payload.get("label") if "label" in payload else None,
            expires_in_days=(
                payload.get("expires_in_days") if "expires_in_days" in payload else None
            ),
        )
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    if record is None:
        return JSONResponse({"ok": False, "error": "unknown key"}, status_code=404)
    log(
        f"  {BG_GREEN}{BOLD} KEY {RESET} {GREEN}updated {record['id']} "
        f"('{record['label']}' → {proxy_keys.key_status(record)}){RESET}"
    )
    return {"ok": True, "key": proxy_keys.public_view(record)}


@router.post("/keys/delete")
async def keys_delete(request: Request):
    """Destroy a key. Immediate: the next request carrying it gets a 403."""
    denied = _forbidden_if_not_admin(request)
    if denied is not None:
        return denied
    payload = await _json_body(request)
    key_id = str(payload.get("id") or "")
    if not proxy_keys.delete_key(key_id):
        return JSONResponse({"ok": False, "error": "unknown key"}, status_code=404)
    log(f"  {BG_GREEN}{BOLD} KEY {RESET} {GREEN}deleted {key_id}{RESET}")
    return {"ok": True, "id": key_id}
