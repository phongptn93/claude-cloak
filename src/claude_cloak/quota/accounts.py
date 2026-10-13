"""Per-account attribution and rate limits, for proxies shared by several
Claude subscriptions.

Rate-limit headers describe the account that answered, so a single global
snapshot flips between accounts on every response. Each request is keyed to
its account instead:

1. ``metadata.user_id`` in the /v1/messages body. Claude Code embeds the
   account UUID there (``user_<hash>_account_<uuid>_session_<uuid>``, or a
   JSON string with ``account_uuid`` in newer builds).
2. The ``anthropic-organization-id`` response header, when the body had none.

Only the UUID is kept — never the token — and it is shown shortened unless
ACCOUNT_LABELS names it.
"""

from __future__ import annotations

import json
import re
from datetime import datetime

from .. import settings, state

_UUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
_ACCOUNT_IN_USER_ID = re.compile(rf"account_({_UUID})")
_UNIFIED_UTIL_RE = re.compile(r"^unified-(.+)-utilization$")
MAX_ACCOUNTS = 50


def account_from_body(body: bytes, content_type: str | None, path: str) -> str | None:
    """Account UUID from a Claude Code /v1/messages body, or None."""
    if not body or "v1/messages" not in path:
        return None
    if not content_type or "json" not in content_type.lower():
        return None
    if b"user_id" not in body:
        return None
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    meta = data.get("metadata") if isinstance(data, dict) else None
    user_id = meta.get("user_id") if isinstance(meta, dict) else None
    if not isinstance(user_id, str):
        return None
    if user_id.startswith("{"):
        try:
            parsed = json.loads(user_id)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, dict) and isinstance(parsed.get("account_uuid"), str):
            return parsed["account_uuid"].lower() or None
    m = _ACCOUNT_IN_USER_ID.search(user_id)
    return m.group(1).lower() if m else None


def resolve_account(from_body: str | None, response_headers) -> str | None:
    if from_body:
        return from_body
    org = response_headers.get("anthropic-organization-id")
    return f"org:{org.lower()}" if org else None


def account_label(account: str) -> str:
    """Operator-given name (ACCOUNT_LABELS, matched by id prefix) or a short id."""
    bare = account.removeprefix("org:")
    for prefix, name in settings.ACCOUNT_LABELS.items():
        if bare.startswith(prefix.lower()):
            return name
    return ("org " if account.startswith("org:") else "") + bare[:8]


def _bucket(account: str) -> dict:
    accounts = state.quota_stats["accounts"]
    b = accounts.get(account)
    if b is None:
        b = accounts[account] = {
            "account": account,
            "requests": 0,
            "cost_usd": 0.0,
            "users": {},
            "rate_limits": {},
            "rate_limits_updated_at": None,
            "first_seen": datetime.now().isoformat(timespec="seconds"),
            "last_seen": None,
        }
        if len(accounts) > MAX_ACCOUNTS:
            oldest = min(accounts, key=lambda k: accounts[k].get("last_seen") or "")
            del accounts[oldest]
    return b


def record_account_rate_limits(account: str | None, latest: dict) -> None:
    if not account or not latest:
        return
    b = _bucket(account)
    b["rate_limits"] = latest
    b["rate_limits_updated_at"] = datetime.now().isoformat(timespec="seconds")


def record_account_usage(account: str | None, cost: float, user_label: str | None) -> None:
    if not account:
        return
    b = _bucket(account)
    b["requests"] += 1
    b["cost_usd"] += cost
    b["last_seen"] = datetime.now().isoformat(timespec="seconds")
    if user_label:
        b["users"][user_label] = b["users"].get(user_label, 0) + 1


def reset_account_usage() -> None:
    """Monthly reset: counters restart, ids and last rate limits stay."""
    for b in state.quota_stats["accounts"].values():
        b["requests"] = 0
        b["cost_usd"] = 0.0
        b["users"] = {}


def unified_windows(rl: dict) -> list[dict]:
    """Subscription (OAuth) limits from ``anthropic-ratelimit-unified-*``.

    Claude Code on a Pro/Max plan never gets the API-key style
    ``requests-remaining`` headers; it gets a utilization fraction and a
    unix reset time per window (5h, 7d, ...).
    """
    out = []
    for key, value in rl.items():
        m = _UNIFIED_UTIL_RE.match(key)
        if not m:
            continue
        window = m.group(1)
        try:
            utilization = float(value)
        except (TypeError, ValueError):
            continue
        reset = rl.get(f"unified-{window}-reset")
        try:
            reset_iso = datetime.fromtimestamp(int(float(reset))).isoformat(timespec="seconds")
        except (TypeError, ValueError, OverflowError, OSError):
            reset_iso = reset
        out.append(
            {
                "window": window,
                "utilization": utilization,
                "status": rl.get(f"unified-{window}-status"),
                "reset": reset_iso,
            }
        )
    out.sort(key=lambda w: w["window"])
    return out


def accounts_view() -> list[dict]:
    rows = []
    for b in state.quota_stats["accounts"].values():
        rl = b.get("rate_limits") or {}
        users = b.get("users") or {}
        rows.append(
            {
                "id": b["account"].removeprefix("org:")[:8],
                "label": account_label(b["account"]),
                "source": "organization" if b["account"].startswith("org:") else "account",
                "requests": b.get("requests", 0),
                "cost_usd": round(b.get("cost_usd", 0.0), 4),
                "users": sorted(users, key=users.get, reverse=True),
                "last_seen": b.get("last_seen"),
                "rate_limits": {
                    "unified_status": rl.get("unified-status"),
                    "unified": unified_windows(rl),
                    "retry_after": rl.get("retry-after"),
                    "updated_at": b.get("rate_limits_updated_at"),
                },
            }
        )
    rows.sort(key=lambda r: r["last_seen"] or "", reverse=True)
    return rows
