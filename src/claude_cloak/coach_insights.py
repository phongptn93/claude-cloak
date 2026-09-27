"""Coach insights: weekly trends, group comparison and data-driven advice.

Everything is derived from counters the proxy already keeps — spend and
tokens per user per day (quota), sessions per day, tool-call counts per week
and per user (coach) — and priced with the live PRICING table. No prompt
text, code or paths are involved. Savings figures are estimates: they reprice
the tokens a user actually sent at another model's rates, which says what
the same traffic would have cost, not whether that model would have done the
work equally well.
"""

from __future__ import annotations

import statistics
from datetime import date, datetime, timedelta
from itertools import pairwise

from . import settings, state
from .pricing import PRICING, cost_of, rates_for
from .quota.activity import group_of

WINDOW_DAYS = 30
WEEKS_SHOWN = 8

# Same-tier successors that are cheaper per token. A recommendation is only
# made when the successor is in PRICING and repricing actually saves money.
SUCCESSOR = {
    "opus-5": "opus-5.5",
    "opus-4.8": "opus-5.5",
    "opus-4.7": "opus-5.5",
    "opus-4.6": "opus-5.5",
    "opus-4.5": "opus-5.5",
    "opus-4.1": "opus-5.5",
    "opus-4": "opus-5.5",
    "opus-3": "opus-5.5",
    "sonnet-4.6": "sonnet-5",
    "sonnet-4": "sonnet-5",
    "sonnet-3.7": "sonnet-5",
    "sonnet-3.5": "sonnet-5",
}
TOP_TIER = ("fable", "mythos", "opus")
EVERYDAY_MODEL = "sonnet-5"
SHIFT_SHARE = 0.3  # share of top-tier traffic assumed movable to EVERYDAY_MODEL


def _tokens(row: dict) -> dict:
    return {
        f: row.get(f, 0) or 0
        for f in (
            "input_tokens",
            "output_tokens",
            "cache_read_input_tokens",
            "cache_creation_input_tokens",
        )
    }


def _is_top_tier(key: str) -> bool:
    return key.startswith(TOP_TIER)


def _unit_of(label: str) -> str:
    return group_of(label) if settings.USER_GROUPS else label


def _unit_name(unit: str) -> str:
    if settings.USER_GROUPS and not unit:
        return "Chưa phân nhóm"
    return unit or "(không nhãn)"


# ---------------------------------------------------------------------------
# Weekly trend
# ---------------------------------------------------------------------------


def _week_start(d: date) -> date:
    return d - timedelta(days=d.weekday())


def _week_key(d: date) -> str:
    y, w, _ = d.isocalendar()
    return f"{y}-W{w:02d}"


def weekly_trend() -> list[dict]:
    today = datetime.now().date()
    by_day = state.quota_stats["by_day"]
    by_day_session = state.quota_stats["by_day_session"]
    by_week = state.coach_stats.get("by_week", {})

    starts = {_week_start(date.fromisoformat(d)) for d in by_day}
    for key in by_week:
        y, w = key.split("-W")
        starts.add(date.fromisocalendar(int(y), int(w), 1))
    weeks = sorted(starts)[-WEEKS_SHOWN:]

    out = []
    for start in weeks:
        end = start + timedelta(days=6)
        cost = requests = in_t = cr_t = days = 0
        sessions: set[str] = set()
        tracked = False
        d = start
        while d <= end:
            row = by_day.get(d.isoformat())
            if row:
                days += 1
                cost += row.get("cost_usd", 0.0) or 0.0
                requests += row.get("requests", 0) or 0
                in_t += row.get("input_tokens", 0) or 0
                cr_t += row.get("cache_read_input_tokens", 0) or 0
            if d.isoformat() in by_day_session:
                tracked = True
                sessions.update(by_day_session[d.isoformat()])
            d += timedelta(days=1)
        c = by_week.get(_week_key(start), {})
        results = c.get("tool_results", 0)
        edits = c.get("edits", 0)
        out.append(
            {
                "week": _week_key(start),
                "start": start.isoformat(),
                "end": end.isoformat(),
                "partial": start <= today <= end,
                "days_with_data": days,
                "cost_usd": round(cost, 4),
                "requests": requests,
                "sessions": len(sessions) if tracked else None,
                "cost_per_request": round(cost / requests, 6) if requests else None,
                "cost_per_session": round(cost / len(sessions), 4) if sessions else None,
                "cache_hit_rate": round(cr_t / (in_t + cr_t), 4) if in_t + cr_t else None,
                "turns": c.get("turns", 0),
                "error_rate": round(c.get("tool_errors", 0) / results, 4) if results else None,
                "reads_per_edit": round(c.get("reads", 0) / edits, 2) if edits else None,
            }
        )
    for prev, cur in pairwise(out):
        cur["cost_change"] = (
            round((cur["cost_usd"] - prev["cost_usd"]) / prev["cost_usd"], 4)
            if prev["cost_usd"]
            else None
        )
    if out:
        out[0]["cost_change"] = None
    return out


# ---------------------------------------------------------------------------
# Group / user comparison
# ---------------------------------------------------------------------------


def _score(discipline, reliability, cache) -> int | None:
    parts = {"discipline": discipline, "reliability": reliability, "cache": cache}
    weights = {"discipline": 0.40, "reliability": 0.35, "cache": 0.25}
    have = {k: v for k, v in parts.items() if v is not None}
    if not have:
        return None
    return round(sum(v * weights[k] for k, v in have.items()) / sum(weights[k] for k in have))


def unit_stats() -> list[dict]:
    today = datetime.now().date()
    since = (today - timedelta(days=WINDOW_DAYS - 1)).isoformat()
    units: dict[str, dict] = {}

    def unit(label: str) -> dict:
        key = _unit_of(label)
        return units.setdefault(
            key,
            {
                "unit": key,
                "name": _unit_name(key),
                "users": set(),
                "cost_usd": 0.0,
                "requests": 0,
                **_tokens({}),
                "sessions": set(),
                "session_cost": 0.0,
                "models": {},
                "turns": 0,
                "tool_results": 0,
                "tool_errors": 0,
                "reads": 0,
                "edits": 0,
            },
        )

    for day, by_label in state.quota_stats["by_day_user"].items():
        if day < since:
            continue
        for label, row in by_label.items():
            u = unit(label)
            u["users"].add(label)
            u["cost_usd"] += row.get("cost_usd", 0.0) or 0.0
            u["requests"] += row.get("requests", 0) or 0
            for f, n in _tokens(row).items():
                u[f] += n
    for day, by_sid in state.quota_stats["by_day_session"].items():
        if day < since:
            continue
        for sid, s in by_sid.items():
            label = s.get("user_label") or ""
            if not label:
                continue
            u = unit(label)
            u["sessions"].add(sid)
            u["session_cost"] += s.get("cost_usd", 0.0) or 0.0
    # Model mix comes from the per-user buckets, which cover the current
    # quota period rather than the rolling window.
    for label, b in state.quota_stats["by_user"].items():
        for key, m in (b.get("models") or {}).items():
            if not isinstance(m, dict):
                continue
            u = unit(label)
            u["users"].add(label)
            agg = u["models"].setdefault(key, {"requests": 0, "cost_usd": 0.0, **_tokens({})})
            agg["requests"] += m.get("requests", 0) or 0
            agg["cost_usd"] += m.get("cost_usd", 0.0) or 0.0
            for f, n in _tokens(m).items():
                agg[f] += n
    for label, c in state.coach_stats.get("by_user", {}).items():
        u = unit(label)
        u["users"].add(label)
        for f in ("turns", "tool_results", "tool_errors", "reads", "edits"):
            u[f] += c.get(f, 0)

    out = []
    for u in units.values():
        denom = u["input_tokens"] + u["cache_read_input_tokens"]
        hit = u["cache_read_input_tokens"] / denom if denom else None
        mix_cost = sum(m["cost_usd"] for m in u["models"].values())
        top_cost = sum(m["cost_usd"] for k, m in u["models"].items() if _is_top_tier(k))
        err = u["tool_errors"] / u["tool_results"] if u["tool_results"] else None
        discipline = min(100.0, u["reads"] / u["edits"] * 100) if u["edits"] else None
        reliability = (1 - err) * 100 if err is not None else None
        cache_score = min(100.0, hit / 0.85 * 100) if hit is not None else None
        n_sessions = len(u["sessions"])
        out.append(
            {
                "unit": u["unit"],
                "name": u["name"],
                "users": sorted(u["users"]),
                "cost_usd": round(u["cost_usd"], 4),
                "requests": u["requests"],
                "sessions": n_sessions,
                "cost_per_session": round(u["session_cost"] / n_sessions, 4)
                if n_sessions
                else None,
                "cost_per_request": round(u["cost_usd"] / u["requests"], 6)
                if u["requests"]
                else None,
                "cache_hit_rate": round(hit, 4) if hit is not None else None,
                "top_tier_cost_share": round(top_cost / mix_cost, 4) if mix_cost else None,
                "error_rate": round(err, 4) if err is not None else None,
                "reads_per_edit": round(u["reads"] / u["edits"], 2) if u["edits"] else None,
                "turns": u["turns"],
                "score": _score(discipline, reliability, cache_score),
                "_raw": u,
            }
        )
    out.sort(key=lambda x: x["cost_usd"], reverse=True)
    return out


# ---------------------------------------------------------------------------
# Recommendations
# ---------------------------------------------------------------------------


def _reprice(tokens: dict, key: str) -> float:
    return cost_of(rates_for(key), tokens)


def _blended_rate(models: dict, tier: str) -> float | None:
    weight = sum(m["input_tokens"] + m["cache_read_input_tokens"] for m in models.values())
    if not weight:
        return None
    return (
        sum(
            (m["input_tokens"] + m["cache_read_input_tokens"]) * rates_for(k)[tier]
            for k, m in models.items()
        )
        / weight
    )


def _money(v: float) -> str:
    return f"${v:,.2f}"


def recommendations(units: list[dict], weeks: list[dict]) -> list[dict]:
    recs: list[dict] = []
    who = "nhóm" if settings.USER_GROUPS else "người dùng"

    # 1. A cheaper model in the same tier (whole team, current period).
    for key, m in state.quota_stats["by_model"].items():
        alt = SUCCESSOR.get(key)
        if not alt or alt not in PRICING or key not in PRICING:
            continue
        tokens = _tokens(m)
        now, then = _reprice(tokens, key), _reprice(tokens, alt)
        saving = now - then
        if saving < 0.5:
            continue
        users = sorted(
            (
                (label, (b.get("models") or {}).get(key, {}).get("cost_usd", 0.0))
                for label, b in state.quota_stats["by_user"].items()
            ),
            key=lambda x: x[1],
            reverse=True,
        )
        top = [label for label, c in users if c > 0][:3]
        recs.append(
            {
                "kind": "model",
                "severity": "warn",
                "scope": "all",
                "target": key,
                "title": f"Chuyển {key} → {alt}: cùng hạng, rẻ hơn {round(saving / now * 100)}%",
                "detail": (
                    f"Kỳ này tiêu {_money(now)} trên {key}. Cùng lượng token đó trên {alt} là "
                    f"{_money(then)}." + (f" Dùng nhiều nhất: {', '.join(top)}." if top else "")
                ),
                "savings_usd": round(saving, 2),
                "savings_window": "kỳ hiện tại",
            }
        )

    # 2. Heavy top-tier use: estimate moving part of it to the everyday model.
    for u in units:
        raw = u["_raw"]
        top = {k: m for k, m in raw["models"].items() if _is_top_tier(k)}
        top_cost = sum(m["cost_usd"] for m in top.values())
        share = u["top_tier_cost_share"]
        if not top or share is None or share < 0.6 or top_cost < 2 or EVERYDAY_MODEL not in PRICING:
            continue
        now = sum(_reprice(_tokens(m), k) for k, m in top.items())
        alt = sum(_reprice(_tokens(m), EVERYDAY_MODEL) for m in top.values())
        saving = (now - alt) * SHIFT_SHARE
        if saving < 0.5:
            continue
        reqs = sum(m["requests"] for m in top.values())
        out_per_req = sum(m["output_tokens"] for m in top.values()) / reqs if reqs else 0
        recs.append(
            {
                "kind": "model",
                "severity": "info",
                "scope": "group" if settings.USER_GROUPS else "user",
                "target": u["name"],
                "title": f"{u['name']}: {round(share * 100)}% chi phí nằm ở Opus/Fable",
                "detail": (
                    f"Trung bình {round(out_per_req):,} token output mỗi request trên model cao cấp. "
                    f"Nếu {int(SHIFT_SHARE * 100)}% số lượt đó (đọc code, sửa nhỏ, chạy test) chuyển sang "
                    f"{EVERYDAY_MODEL}, chi phí giảm khoảng {_money(saving)}. "
                    "Giữ Opus/Fable cho thiết kế và debug khó."
                ),
                "savings_usd": round(saving, 2),
                "savings_window": "kỳ hiện tại",
            }
        )

    # 3. Cache hit well below the team's typical level.
    hits = [u["cache_hit_rate"] for u in units if u["cache_hit_rate"] is not None]
    target = min(0.9, max(0.6, statistics.median(hits))) if hits else 0.6
    for u in units:
        raw = u["_raw"]
        hit = u["cache_hit_rate"]
        volume = raw["input_tokens"] + raw["cache_read_input_tokens"]
        if hit is None or volume < 2_000_000 or hit >= target - 0.1:
            continue
        r_in = _blended_rate(raw["models"], "input") or rates_for("unknown")["input"]
        r_read = _blended_rate(raw["models"], "cache_read") or rates_for("unknown")["cache_read"]
        extra = target * volume - raw["cache_read_input_tokens"]
        saving = extra * (r_in - r_read) / 1_000_000
        if saving < 0.5:
            continue
        recs.append(
            {
                "kind": "cache",
                "severity": "warn",
                "scope": "group" if settings.USER_GROUPS else "user",
                "target": u["name"],
                "title": f"{u['name']}: cache hit {round(hit * 100)}%, thấp hơn mức chung {round(target * 100)}%",
                "detail": (
                    f"{volume / 1e6:,.1f}M token input trong {WINDOW_DAYS} ngày, phần lớn trả giá đầy đủ. "
                    "Giữ nguyên CLAUDE.md, danh sách tool và model trong một phiên (đổi bất kỳ thứ nào "
                    "cũng làm mất cache), tránh để phiên nghỉ quá 5 phút giữa các lượt. "
                    f"Đạt mức {round(target * 100)}% sẽ tiết kiệm khoảng {_money(saving)}."
                ),
                "savings_usd": round(saving, 2),
                "savings_window": f"{WINDOW_DAYS} ngày",
            }
        )

    # 4. Cache written but rarely read back — paying the write premium for nothing.
    for u in units:
        raw = u["_raw"]
        cw, cr = raw["cache_creation_input_tokens"], raw["cache_read_input_tokens"]
        if cw < 1_000_000 or cr >= cw:
            continue
        r_in = _blended_rate(raw["models"], "input") or rates_for("unknown")["input"]
        r_w = (
            _blended_rate(raw["models"], "cache_write_5m") or rates_for("unknown")["cache_write_5m"]
        )
        premium = cw * (r_w - r_in) / 1_000_000
        if premium < 0.5:
            continue
        recs.append(
            {
                "kind": "cache",
                "severity": "info",
                "scope": "group" if settings.USER_GROUPS else "user",
                "target": u["name"],
                "title": f"{u['name']}: ghi cache nhiều hơn đọc lại",
                "detail": (
                    f"{cw / 1e6:,.1f}M token ghi vào cache nhưng chỉ {cr / 1e6:,.1f}M được đọc lại. "
                    "Thường do phiên rất ngắn hoặc context thay đổi liên tục. Gộp việc liên quan vào một "
                    f"phiên dài hơn. Phần phụ phí ghi cache là khoảng {_money(premium)}."
                ),
                "savings_usd": round(premium, 2),
                "savings_window": f"{WINDOW_DAYS} ngày",
            }
        )

    # 5. Sessions far more expensive than the team's typical session.
    cps = [u["cost_per_session"] for u in units if u["cost_per_session"] and u["sessions"] >= 3]
    if len(cps) >= 2:
        median_cps = statistics.median(cps)
        for u in units:
            c = u["cost_per_session"]
            if not c or u["sessions"] < 3 or c < 1 or c <= 2 * median_cps:
                continue
            recs.append(
                {
                    "kind": "session",
                    "severity": "info",
                    "scope": "group" if settings.USER_GROUPS else "user",
                    "target": u["name"],
                    "title": f"{u['name']}: {_money(c)}/phiên, gấp {c / median_cps:.1f}× mức chung",
                    "detail": (
                        f"{u['sessions']} phiên trong {WINDOW_DAYS} ngày. Phiên dài kéo theo context lớn ở mỗi lượt. "
                        "Dùng /compact khi context đã dài, hoặc /clear khi chuyển sang việc khác."
                    ),
                    "savings_usd": None,
                    "savings_window": None,
                }
            )

    # 6. Tool reliability.
    for u in units:
        raw = u["_raw"]
        err = u["error_rate"]
        if err is None or raw["tool_results"] < 50 or err <= 0.15:
            continue
        recs.append(
            {
                "kind": "reliability",
                "severity": "warn",
                "scope": "group" if settings.USER_GROUPS else "user",
                "target": u["name"],
                "title": f"{u['name']}: {round(err * 100)}% tool call bị lỗi",
                "detail": (
                    f"{raw['tool_errors']:,}/{raw['tool_results']:,} kết quả tool báo lỗi. Mỗi lỗi tốn thêm một lượt "
                    "với toàn bộ context. Kiểm tra đường dẫn, quyền và lệnh build/test trong CLAUDE.md."
                ),
                "savings_usd": None,
                "savings_window": None,
            }
        )

    # 7. Week-over-week jump in spend (complete weeks only).
    full = [w for w in weeks if not w["partial"]]
    if len(full) >= 2:
        prev, last = full[-2], full[-1]
        delta = last["cost_usd"] - prev["cost_usd"]
        if prev["cost_usd"] and delta >= 5 and delta / prev["cost_usd"] >= 0.3:
            recs.append(
                {
                    "kind": "trend",
                    "severity": "warn",
                    "scope": "all",
                    "target": last["week"],
                    "title": f"Chi phí tuần {last['week']} tăng {round(delta / prev['cost_usd'] * 100)}%",
                    "detail": (
                        f"{_money(last['cost_usd'])} so với {_money(prev['cost_usd'])} tuần trước "
                        f"({last['requests']:,} so với {prev['requests']:,} request). "
                        f"Xem tab Activity để biết {who} nào tăng."
                    ),
                    "savings_usd": None,
                    "savings_window": None,
                }
            )

    order = {"warn": 0, "info": 1}
    recs.sort(key=lambda r: (-(r["savings_usd"] or 0), order.get(r["severity"], 2)))
    return recs[:12]


def coach_insights() -> dict:
    weeks = weekly_trend()
    units = unit_stats()
    recs = recommendations(units, weeks)
    for u in units:
        u.pop("_raw", None)
    return {
        "window_days": WINDOW_DAYS,
        "group_by": "group" if settings.USER_GROUPS else "user",
        "weekly": weeks,
        "groups": units,
        "recommendations": recs,
    }
