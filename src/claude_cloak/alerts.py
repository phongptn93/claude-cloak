"""Push alerts to a webhook (Slack incoming webhook or plain JSON).

Off unless ALERT_WEBHOOK_URL is set. Each alert has a key; a key fires once
and then stays quiet until its cooldown passes, or — for keys that embed the
period or reset time — until that period ends. Sending never blocks or
fails a request: it runs as a background task on the telemetry client.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from datetime import datetime

from . import settings, state
from .terminal import DIM, RESET, YELLOW, log

_sent: dict[str, float] = {}
_tasks: set[asyncio.Task] = set()
_MAX_KEYS = 2000


def notify(key: str, level: str, text: str, cooldown_s: float | None = None) -> bool:
    """Queue an alert unless ``key`` already fired within its cooldown.

    ``cooldown_s=None`` means once per key for the life of the process.
    Returns True when an alert was queued.
    """
    if not settings.ALERT_WEBHOOK_URL:
        return False
    now = time.monotonic()
    last = _sent.get(key)
    if last is not None and (cooldown_s is None or now - last < cooldown_s):
        return False
    _sent[key] = now
    if len(_sent) > _MAX_KEYS:
        _sent.pop(next(iter(_sent)))
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return False
    task = loop.create_task(_send(key, level, text))
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)
    return True


def _payload(key: str, level: str, text: str) -> dict:
    icon = {"danger": ":red_circle:", "warn": ":large_yellow_circle:"}.get(
        level, ":information_source:"
    )
    if settings.ALERT_WEBHOOK_FORMAT == "json":
        return {
            "source": "claude-cloak",
            "key": key,
            "level": level,
            "text": text,
            "at": datetime.now().isoformat(timespec="seconds"),
        }
    return {"text": f"{icon} *claude-cloak* — {text}"}


async def _send(key: str, level: str, text: str) -> None:
    client = state.runtime.telemetry_client
    if client is None:
        return
    try:
        resp = await client.post(settings.ALERT_WEBHOOK_URL, json=_payload(key, level, text))
        if resp.status_code >= 400:
            log(f"  {YELLOW}alert webhook answered {resp.status_code} for {key}{RESET}")
        else:
            log(f"  {DIM}alert sent: {key}{RESET}")
    except Exception as exc:  # network, timeout — alerts are best effort
        log(f"  {YELLOW}alert webhook failed ({type(exc).__name__}) for {key}{RESET}")


async def drain() -> None:
    """Let in-flight alerts finish on shutdown."""
    if _tasks:
        with contextlib.suppress(Exception):
            await asyncio.wait(list(_tasks), timeout=5)


# --- the alerts themselves ----------------------------------------------------


def check_account_limits(label: str, account: str, windows: list[dict]) -> None:
    for w in windows:
        used = w.get("utilization")
        if not isinstance(used, (int, float)) or used < settings.ALERT_ACCOUNT_THRESHOLD:
            continue
        # Once per window per reset: the next window gets its own alert.
        notify(
            f"account:{account}:{w['window']}:{w.get('reset')}",
            "danger" if used >= 0.95 else "warn",
            f"Tài khoản *{label}*: khung {w['window']} đã dùng {used * 100:.0f}%"
            + (f", reset lúc {w['reset']}" if w.get("reset") else ""),
        )


def check_user_cap(label: str, used: float, cap: float, period_key: str | None) -> None:
    if cap <= 0:
        return
    pct = used / cap
    if pct >= 1:
        notify(
            f"cap:{label}:{period_key}:over",
            "danger",
            f"User *{label}* đã vượt hạn mức: ${used:,.2f} / ${cap:,.2f}"
            + (" — request mới bị chặn (429)" if settings.USER_QUOTA_HARD_LIMIT else ""),
        )
    elif pct >= 0.8:
        notify(
            f"cap:{label}:{period_key}:near",
            "warn",
            f"User *{label}* đã dùng {pct * 100:.0f}% hạn mức (${used:,.2f} / ${cap:,.2f})",
        )


def check_stall(req_id: int) -> None:
    notify(
        "stall",
        "warn",
        f"Stream #{req_id} bị stall (upstream im lặng {settings.UPSTREAM_STALL_SECONDS:.0f}s). "
        f"Tổng {state.stream_stats['stalls']} stall / {state.stream_stats['streams_started']} stream.",
        cooldown_s=settings.ALERT_COOLDOWN_MINUTES * 60,
    )
