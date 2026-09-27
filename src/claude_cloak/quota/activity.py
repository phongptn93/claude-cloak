"""Day × user × session views over the persisted per-day buckets.

Everything here is derived from quota_stats at request time — nothing new is
recorded. `by_day_user` carries spend and tokens per user per day for the
whole retained history; `by_day_session` adds the session dimension from
schema v5 on, so days recorded before that report `sessions: None` rather
than a misleading zero.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta

from .. import settings, state

TOKEN_FIELDS = (
    "input_tokens",
    "output_tokens",
    "cache_read_input_tokens",
    "cache_creation_input_tokens",
)


def group_of(label: str | None) -> str:
    """Reporting group for a user label ('' when USER_GROUPS has no entry)."""
    return settings.USER_GROUPS.get(label or "", "")


def _empty() -> dict:
    return {"sessions": 0, "requests": 0, "cost_usd": 0.0, **dict.fromkeys(TOKEN_FIELDS, 0)}


def _add(acc: dict, row: dict, sessions: int | None) -> None:
    acc["requests"] += row.get("requests", 0) or 0
    acc["cost_usd"] += float(row.get("cost_usd", 0.0) or 0.0)
    for f in TOKEN_FIELDS:
        acc[f] += row.get(f, 0) or 0
    if sessions is None:
        acc["sessions_known"] = False
    else:
        acc["sessions"] += sessions


def _finish(acc: dict) -> dict:
    out = dict(acc)
    known = out.pop("sessions_known", True)
    if not known and out["sessions"] == 0:
        out["sessions"] = None
    out["cost_usd"] = round(out["cost_usd"], 6)
    s = out["sessions"]
    out["cost_per_session"] = round(out["cost_usd"] / s, 6) if s else None
    out["requests_per_session"] = round(out["requests"] / s, 2) if s else None
    denom = out["input_tokens"] + out["cache_read_input_tokens"]
    out["cache_hit_rate"] = round(out["cache_read_input_tokens"] / denom, 4) if denom else None
    return out


def _sessions_for(day: str) -> dict[str, dict] | None:
    """The day's session buckets, or None when that day predates tracking."""
    return state.quota_stats["by_day_session"].get(day)


def day_user_rows(days: int) -> list[dict]:
    """One entry per day (newest first), each with its per-user rows."""
    by_day = state.quota_stats["by_day"]
    by_day_user = state.quota_stats["by_day_user"]
    out = []
    for day in sorted(by_day, reverse=True)[:days]:
        sessions = _sessions_for(day)
        per_user: dict[str, list[dict]] = {}
        if sessions is not None:
            for s in sessions.values():
                per_user.setdefault(s.get("user_label") or "", []).append(s)
        users = []
        labels = set(by_day_user.get(day, {})) | ({k for k in per_user if k} if sessions else set())
        for label in labels:
            row = by_day_user.get(day, {}).get(label)
            if row is None:  # session seen but no labelled usage row
                row = _empty()
                for s in per_user.get(label, []):
                    _add(row, s, 0)
            acc = _empty()
            _add(acc, row, len(per_user.get(label, [])) if sessions is not None else None)
            view = _finish(acc)
            view.update(
                user_label=label,
                group=group_of(label),
                first_seen=min(
                    (s.get("first_seen") or "" for s in per_user.get(label, [])), default=None
                )
                or None,
                last_seen=max(
                    (s.get("last_seen") or "" for s in per_user.get(label, [])), default=None
                )
                or None,
            )
            users.append(view)
        users.sort(key=lambda u: u["cost_usd"], reverse=True)
        d = by_day[day]
        total = _empty()
        _add(total, d, len(sessions) if sessions is not None else None)
        entry = _finish(total)
        entry.update(date=day, users=users)
        out.append(entry)
    return out


def _window(rows_by_day: dict[str, dict], start: date, end: date) -> dict:
    acc = _empty()
    d = start
    while d <= end:
        key = d.isoformat()
        if key in rows_by_day:
            r = rows_by_day[key]
            _add(acc, r, r.get("sessions"))
        d += timedelta(days=1)
    return _finish(acc)


def activity_view(days: int = 30) -> dict:
    """Payload for GET /quota/activity."""
    days = max(1, min(days, settings.QUOTA_MAX_DAYS))
    today = datetime.now().date()
    yesterday = today - timedelta(days=1)
    rows = day_user_rows(settings.QUOTA_MAX_DAYS)

    # label -> date -> row, for the rolling windows below.
    per_user: dict[str, dict[str, dict]] = {}
    for day in rows:
        for u in day["users"]:
            per_user.setdefault(u["user_label"], {})[day["date"]] = u

    spark_days = [(today - timedelta(days=i)).isoformat() for i in range(13, -1, -1)]
    users = []
    for label, by_date in per_user.items():
        users.append(
            {
                "user_label": label,
                "group": group_of(label),
                "today": _window(by_date, today, today),
                "yesterday": _window(by_date, yesterday, yesterday),
                "last_7d": _window(by_date, today - timedelta(days=6), today),
                "prev_7d": _window(by_date, today - timedelta(days=13), today - timedelta(days=7)),
                "days_active": len(by_date),
                "last_active": max(by_date),
                "daily_cost": [
                    round(by_date.get(d, {}).get("cost_usd", 0.0), 6) for d in spark_days
                ],
                "daily_sessions": [by_date.get(d, {}).get("sessions") for d in spark_days],
            }
        )
    users.sort(key=lambda u: (u["last_7d"]["cost_usd"], u["today"]["cost_usd"]), reverse=True)

    groups: dict[str, dict] = {}
    for u in users:
        g = groups.setdefault(
            u["group"],
            {
                "group": u["group"],
                "users": 0,
                **{w: _empty() for w in ("today", "yesterday", "last_7d", "prev_7d")},
            },
        )
        g["users"] += 1
        for w in ("today", "yesterday", "last_7d", "prev_7d"):
            _add(g[w], u[w], u[w]["sessions"])
    group_list = []
    for g in groups.values():
        group_list.append(
            {**g, **{w: _finish(g[w]) for w in ("today", "yesterday", "last_7d", "prev_7d")}}
        )
    group_list.sort(key=lambda g: g["last_7d"]["cost_usd"], reverse=True)

    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "today": today.isoformat(),
        "yesterday": yesterday.isoformat(),
        "groups_configured": bool(settings.USER_GROUPS),
        "session_tracking_since": min(state.quota_stats["by_day_session"], default=None),
        "spark_days": spark_days,
        "days": rows[:days],
        "users": users,
        "groups": group_list,
    }


def day_sessions_view(day: str, user: str | None = None) -> dict:
    """Payload for GET /quota/activity/{day}: that day's sessions, newest first."""
    sessions = _sessions_for(day)
    items = []
    for s in (sessions or {}).values():
        if user is not None and (s.get("user_label") or "") != user:
            continue
        items.append(
            {
                **{
                    k: s.get(k)
                    for k in ("session_id", "user_label", "requests", "first_seen", "last_seen")
                },
                **{f: s.get(f, 0) for f in TOKEN_FIELDS},
                "group": group_of(s.get("user_label")),
                "cost_usd": round(float(s.get("cost_usd", 0.0) or 0.0), 6),
                "models": s.get("models", {}),
            }
        )
    items.sort(key=lambda s: s.get("last_seen") or "", reverse=True)
    return {"date": day, "user": user, "tracked": sessions is not None, "sessions": items}
