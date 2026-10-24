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
from .quota.accounts import accounts_view
from .quota.activity import group_of
from .quota.cache_ttl import cache_ttl_view

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
EVERYDAY_MODEL = "sonnet-5.5"
CONTEXT_FLOOR = 150_000  # context per request below this is never flagged
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


def _prompt_tokens(row: dict) -> int:
    """Every prompt token: fresh input, cache reads and cache writes."""
    return row["input_tokens"] + row["cache_read_input_tokens"] + row["cache_creation_input_tokens"]


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
        cost = requests = in_t = cr_t = cw_t = days = 0
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
                cw_t += row.get("cache_creation_input_tokens", 0) or 0
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
                "cache_hit_rate": round(cr_t / (in_t + cr_t + cw_t), 4)
                if in_t + cr_t + cw_t
                else None,
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


def _add_model(models: dict, key: str, m: dict) -> None:
    agg = models.setdefault(key, {"requests": 0, "cost_usd": 0.0, **_tokens({})})
    agg["requests"] += m.get("requests", 0) or 0
    agg["cost_usd"] += m.get("cost_usd", 0.0) or 0.0
    for f, n in _tokens(m).items():
        agg[f] += n


def _window_start() -> str:
    return (datetime.now().date() - timedelta(days=WINDOW_DAYS - 1)).isoformat()


def unit_stats() -> list[dict]:
    since = _window_start()
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
            # Model mix over the same window. Days recorded before the
            # per-model split existed simply contribute nothing here.
            for key, m in (row.get("models") or {}).items():
                if isinstance(m, dict):
                    _add_model(u["models"], key, m)
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
    for label, c in state.coach_stats.get("by_user", {}).items():
        u = unit(label)
        u["users"].add(label)
        for f in ("turns", "tool_results", "tool_errors", "reads", "edits"):
            u[f] += c.get(f, 0)

    out = []
    for u in units.values():
        denom = _prompt_tokens(u)
        hit = u["cache_read_input_tokens"] / denom if denom else None
        mix_cost = sum(m["cost_usd"] for m in u["models"].values())
        top_cost = sum(m["cost_usd"] for k, m in u["models"].items() if _is_top_tier(k))
        err = u["tool_errors"] / u["tool_results"] if u["tool_results"] else None
        discipline = min(100.0, u["reads"] / u["edits"] * 100) if u["edits"] else None
        reliability = (1 - err) * 100 if err is not None else None
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
                # Prompt tokens sent per request. Every turn re-reads the
                # whole context, so this — not the hit rate — is what drives
                # cache-read spend once caching works.
                "context_per_request": round(denom / u["requests"]) if u["requests"] else None,
                "top_tier_cost_share": round(top_cost / mix_cost, 4) if mix_cost else None,
                "error_rate": round(err, 4) if err is not None else None,
                "reads_per_edit": round(u["reads"] / u["edits"], 2) if u["edits"] else None,
                "turns": u["turns"],
                "_parts": (discipline, reliability),
                "_raw": u,
            }
        )
    # Cache is scored against the team, on the miss rate: hit rates all sit
    # around 95-98%, so a fixed "85% = full marks" gave everyone 100. A unit
    # missing twice as often as the team median scores 50.
    misses = [1 - x["cache_hit_rate"] for x in out if x["cache_hit_rate"] is not None]
    team_miss = statistics.median(misses) if misses else None
    for x in out:
        cache_score = None
        if x["cache_hit_rate"] is not None and team_miss is not None:
            miss = 1 - x["cache_hit_rate"]
            cache_score = 100.0 if miss <= team_miss else team_miss / miss * 100
        x["cache_score"] = round(cache_score) if cache_score is not None else None
        x["score"] = _score(*x.pop("_parts"), cache_score)
    out.sort(key=lambda x: x["cost_usd"], reverse=True)
    return out


# ---------------------------------------------------------------------------
# Recommendations
# ---------------------------------------------------------------------------


def _reprice(tokens: dict, key: str) -> float:
    return cost_of(rates_for(key), tokens)


def _blended_rate(models: dict, tier: str) -> float | None:
    weight = sum(_prompt_tokens(m) for m in models.values())
    if not weight:
        return None
    return sum(_prompt_tokens(m) * rates_for(k)[tier] for k, m in models.items()) / weight


def _cache_write_rate(models: dict) -> float:
    """Blended write rate at the 5m/1h TTL mix actually billed.

    Per-user rows keep no TTL split, so the proxy-wide mix stands in. The
    token saver moves prefixes to the 1h TTL, which bills writes at 2x input
    rather than 1.25x — pricing every write at the 5m rate understated it.
    """
    ut = state.quota_stats["usage_total"]
    w5 = ut.get("cache_creation_5m_input_tokens", 0) or 0
    w1 = ut.get("cache_creation_1h_input_tokens", 0) or 0
    share_1h = w1 / (w5 + w1) if w5 + w1 else 0.0
    fallback = rates_for("unknown")
    r5 = _blended_rate(models, "cache_write_5m") or fallback["cache_write_5m"]
    r1 = _blended_rate(models, "cache_write_1h") or fallback["cache_write_1h"]
    return (1 - share_1h) * r5 + share_1h * r1


def _money(v: float) -> str:
    return f"${v:,.2f}"


def recommendations(units: list[dict], weeks: list[dict]) -> list[dict]:
    recs: list[dict] = []
    who = "nhóm" if settings.USER_GROUPS else "người dùng"

    # 1. A cheaper model in the same tier (whole team, same window).
    team: dict[str, dict] = {}
    per_user: dict[str, dict[str, float]] = {}
    since = _window_start()
    for day, by_label in state.quota_stats["by_day_user"].items():
        if day < since:
            continue
        for label, row in by_label.items():
            for key, m in (row.get("models") or {}).items():
                if not isinstance(m, dict):
                    continue
                _add_model(team, key, m)
                spent = per_user.setdefault(key, {})
                spent[label] = spent.get(label, 0.0) + (m.get("cost_usd", 0.0) or 0.0)
    for key, m in team.items():
        alt = SUCCESSOR.get(key)
        if not alt or alt not in PRICING or key not in PRICING:
            continue
        tokens = _tokens(m)
        now, then = _reprice(tokens, key), _reprice(tokens, alt)
        saving = now - then
        if saving < 0.5:
            continue
        users = sorted(per_user.get(key, {}).items(), key=lambda x: x[1], reverse=True)
        top = [label for label, c in users if c > 0][:3]
        recs.append(
            {
                "kind": "model",
                "severity": "warn",
                "scope": "all",
                "target": key,
                "title": f"Chuyển {key} → {alt}: cùng hạng, rẻ hơn {round(saving / now * 100)}%",
                "detail": (
                    f"{WINDOW_DAYS} ngày qua tiêu {_money(now)} trên {key}. Cùng lượng token đó "
                    f"trên {alt} là {_money(then)}."
                    + (f" Dùng nhiều nhất: {', '.join(top)}." if top else "")
                ),
                "savings_usd": round(saving, 2),
                "savings_window": f"{WINDOW_DAYS} ngày",
                "evidence": [
                    {"label": f"Chi phí trên {key}", "value": _money(now)},
                    {"label": f"Cùng token trên {alt}", "value": _money(then)},
                    {"label": "Request", "value": f"{m['requests']:,}"},
                ],
                "actions": [
                    f"Đổi model mặc định sang {alt} (/model hoặc ANTHROPIC_MODEL trong settings).",
                    "Báo cho " + (", ".join(top) if top else "các thành viên") + " biết model mới.",
                    "Theo dõi chi phí tuần sau trong tab Insights.",
                ],
                "effort": "low",
                "confidence": "high",
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
                "savings_window": f"{WINDOW_DAYS} ngày",
                "evidence": [
                    {"label": "Tỉ lệ chi phí Opus/Fable", "value": f"{round(share * 100)}%"},
                    {"label": "Chi phí Opus/Fable", "value": _money(top_cost)},
                    {"label": "Output / request", "value": f"{round(out_per_req):,} token"},
                ],
                "actions": [
                    f"Dùng {EVERYDAY_MODEL} làm model mặc định cho việc thường ngày.",
                    "Chỉ chuyển sang Opus/Fable (/model) khi thiết kế kiến trúc hoặc debug khó.",
                    "Cân nhắc đặt subagent đọc code/chạy test dùng model rẻ hơn.",
                ],
                "effort": "medium",
                "confidence": "medium",
            }
        )

    # 3. Cache hit well below the team's typical level.
    hits = [u["cache_hit_rate"] for u in units if u["cache_hit_rate"] is not None]
    target = min(0.9, max(0.6, statistics.median(hits))) if hits else 0.6
    for u in units:
        raw = u["_raw"]
        hit = u["cache_hit_rate"]
        volume = _prompt_tokens(raw)
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
                "evidence": [
                    {"label": "Cache hit", "value": f"{round(hit * 100)}%"},
                    {"label": "Mức chung", "value": f"{round(target * 100)}%"},
                    {"label": "Token input", "value": f"{volume / 1e6:,.1f}M"},
                ],
                "actions": [
                    "Giữ nguyên CLAUDE.md, danh sách MCP/tool và model trong suốt một phiên.",
                    "Tránh để phiên nghỉ quá 5 phút giữa các lượt (hoặc dùng TTL 1 giờ).",
                    "Không sửa file CLAUDE.md giữa phiên; sửa xong thì mở phiên mới.",
                ],
                "effort": "low",
                "confidence": "medium",
            }
        )

    # 3b. Context far larger than the team's typical request. Cache reads are
    # cheap per token but are paid on the whole context every turn.
    ctx = [u["context_per_request"] for u in units if u["context_per_request"]]
    if len(ctx) >= 2:
        median_ctx = statistics.median(ctx)
        for u in units:
            raw = u["_raw"]
            c = u["context_per_request"]
            if not c or u["requests"] < 100 or c < CONTEXT_FLOOR or c < 1.5 * median_ctx:
                continue
            r_read = (
                _blended_rate(raw["models"], "cache_read") or rates_for("unknown")["cache_read"]
            )
            saving = (c - median_ctx) * u["requests"] * r_read / 1_000_000
            if saving < 0.5:
                continue
            recs.append(
                {
                    "kind": "context",
                    "severity": "warn",
                    "scope": "group" if settings.USER_GROUPS else "user",
                    "target": u["name"],
                    "title": (
                        f"{u['name']}: {round(c / 1000):,}K token context mỗi request, "
                        f"gấp {c / median_ctx:.1f}× mức chung"
                    ),
                    "detail": (
                        f"Mỗi lượt gửi lại toàn bộ context; mức chung là {round(median_ctx / 1000):,}K. "
                        "Dùng /compact khi phiên đã dài, /clear khi chuyển việc, và tránh đọc cả file lớn "
                        f"khi chỉ cần một đoạn. Về mức chung sẽ tiết kiệm khoảng {_money(saving)}."
                    ),
                    "savings_usd": round(saving, 2),
                    "savings_window": f"{WINDOW_DAYS} ngày",
                    "evidence": [
                        {"label": "Context / request", "value": f"{round(c / 1000):,}K"},
                        {"label": "Mức chung", "value": f"{round(median_ctx / 1000):,}K"},
                        {"label": "Request", "value": f"{u['requests']:,}"},
                    ],
                    "actions": [
                        "Chạy /compact khi phiên đã dài.",
                        "Chạy /clear khi chuyển sang việc khác.",
                        "Đọc đúng đoạn cần (offset/limit, grep) thay vì cả file lớn.",
                    ],
                    "effort": "low",
                    "confidence": "medium",
                }
            )

    # 4. Cache written but rarely read back — paying the write premium for nothing.
    for u in units:
        raw = u["_raw"]
        cw, cr = raw["cache_creation_input_tokens"], raw["cache_read_input_tokens"]
        if cw < 1_000_000 or cr >= cw:
            continue
        r_in = _blended_rate(raw["models"], "input") or rates_for("unknown")["input"]
        r_w = _cache_write_rate(raw["models"])
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
                "evidence": [
                    {"label": "Ghi cache", "value": f"{cw / 1e6:,.1f}M token"},
                    {"label": "Đọc lại", "value": f"{cr / 1e6:,.1f}M token"},
                    {"label": "Phụ phí ghi", "value": _money(premium)},
                ],
                "actions": [
                    "Gộp các việc liên quan vào một phiên dài hơn thay vì nhiều phiên ngắn.",
                    "Tránh đổi model, tool hoặc system prompt giữa chừng.",
                ],
                "effort": "medium",
                "confidence": "medium",
            }
        )

    # 4b. Is the 1h cache TTL paying for itself? (current quota period)
    ttl = cache_ttl_view()
    turns = sum(ttl["gaps"].values())
    if ttl["premium_usd"] >= 5 and turns >= 200:
        by_proxy = ttl["requests_proxy_1h"] > 0
        if ttl["net_usd"] < 0:
            recs.append(
                {
                    "kind": "cache",
                    "severity": "warn",
                    "scope": "all",
                    "target": "cache-ttl",
                    "title": "Cache TTL 1 giờ đang tốn hơn số tiền nó tiết kiệm",
                    "detail": (
                        f"Phụ phí ghi cache 1 giờ kỳ này {_money(ttl['premium_usd'])}, chỉ tiết kiệm "
                        f"{_money(ttl['saved_usd'])} ở những lượt sau khi nghỉ 5–60 phút "
                        f"({round((ttl['share_5m_to_1h'] or 0) * 100)}% số lượt). "
                        + (
                            "Proxy đang tự nâng TTL lên 1 giờ — đặt CACHE_EXTEND_TTL=false."
                            if by_proxy
                            else "Chính Claude Code yêu cầu TTL 1 giờ — đặt CACHE_FORCE_TTL=5m "
                            "để proxy hạ về 5 phút."
                        )
                    ),
                    "savings_usd": round(-ttl["net_usd"], 2),
                    "savings_window": "kỳ này",
                    "evidence": [
                        {"label": "Phụ phí TTL 1h", "value": _money(ttl["premium_usd"])},
                        {"label": "Tiết kiệm được", "value": _money(ttl["saved_usd"])},
                        {
                            "label": "Lượt sau 5–60 phút",
                            "value": f"{round((ttl['share_5m_to_1h'] or 0) * 100)}%",
                        },
                    ],
                    "actions": [
                        "Đặt CACHE_EXTEND_TTL=false trong /config."
                        if by_proxy
                        else "Đặt CACHE_FORCE_TTL=5m trong /config.",
                        "Kiểm tra lại dòng Cache TTL 1h dưới mục này sau một tuần.",
                    ],
                    "effort": "low",
                    "confidence": "high",
                }
            )
        else:
            recs.append(
                {
                    "kind": "cache",
                    "severity": "info",
                    "scope": "all",
                    "target": "cache-ttl",
                    "title": "Cache TTL 1 giờ đang có lời",
                    "detail": (
                        f"Tiết kiệm {_money(ttl['saved_usd'])} ở các lượt sau khi nghỉ 5–60 phút, "
                        f"so với phụ phí {_money(ttl['premium_usd'])}. Giữ nguyên."
                    ),
                    "savings_usd": None,
                    "savings_window": None,
                    "evidence": [
                        {"label": "Tiết kiệm được", "value": _money(ttl["saved_usd"])},
                        {"label": "Phụ phí TTL 1h", "value": _money(ttl["premium_usd"])},
                    ],
                    "actions": ["Không cần làm gì."],
                    "effort": "low",
                    "confidence": "high",
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
                    "evidence": [
                        {"label": "Chi phí / phiên", "value": _money(c)},
                        {"label": "Mức chung", "value": _money(median_cps)},
                        {"label": "Số phiên", "value": f"{u['sessions']:,}"},
                    ],
                    "actions": [
                        "Chia việc lớn thành nhiều phiên ngắn, mỗi phiên một mục tiêu.",
                        "Dùng /compact khi context đã dài, /clear khi chuyển việc.",
                    ],
                    "effort": "medium",
                    "confidence": "low",
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
                "evidence": [
                    {"label": "Tỉ lệ lỗi tool", "value": f"{round(err * 100)}%"},
                    {
                        "label": "Lỗi / tổng",
                        "value": f"{raw['tool_errors']:,} / {raw['tool_results']:,}",
                    },
                ],
                "actions": [
                    "Ghi đúng lệnh build/test/lint vào CLAUDE.md.",
                    "Cấp quyền cho các lệnh hay bị từ chối (settings.json → permissions).",
                    "Kiểm tra đường dẫn và môi trường (venv, node_modules) của dự án.",
                ],
                "effort": "medium",
                "confidence": "medium",
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
                    "evidence": [
                        {"label": f"Tuần {last['week']}", "value": _money(last["cost_usd"])},
                        {"label": f"Tuần {prev['week']}", "value": _money(prev["cost_usd"])},
                        {
                            "label": "Request",
                            "value": f"{prev['requests']:,} → {last['requests']:,}",
                        },
                    ],
                    "actions": [
                        f"Mở tab Activity, xem {who} nào tăng nhiều nhất.",
                        "Xác nhận mức tăng là do khối lượng việc, không phải do phiên lỗi hoặc lặp.",
                    ],
                    "effort": "low",
                    "confidence": "high",
                }
            )

    recs.extend(capacity_recommendations())

    for r in recs:
        _finalize(r)
        _apply_mark(r)
    order = {"high": 0, "medium": 1, "low": 2}
    recs.sort(key=lambda r: (order[r["priority"]], -(r["savings_usd"] or 0)))
    return recs[:MAX_RECS]


MAX_RECS = 16
REC_STATUSES = ("done", "dismissed", "snoozed")
MAX_REC_MARKS = 500
SNOOZE_DAYS_MAX = 90
CATEGORY = {
    "model": "cost",
    "cache": "cost",
    "context": "cost",
    "session": "usage",
    "reliability": "reliability",
    "trend": "usage",
    "capacity": "capacity",
}


def _finalize(r: dict) -> None:
    """Fields every recommendation carries, derived from what the rule set."""
    r.setdefault("evidence", [])
    r.setdefault("actions", [])
    r.setdefault("effort", "medium")
    r.setdefault("confidence", "medium")
    r["id"] = f"{r['kind']}:{r['scope']}:{r['target']}"
    r["category"] = CATEGORY.get(r["kind"], "usage")
    saving = r.get("savings_usd") or 0
    if "priority" not in r:
        if (r["severity"] == "warn" and saving >= 20) or saving >= 100:
            r["priority"] = "high"
        elif r["severity"] == "warn" or saving >= 5:
            r["priority"] = "medium"
        else:
            r["priority"] = "low"


def _apply_mark(r: dict) -> None:
    """Status an admin set on this recommendation; a lapsed snooze is open."""
    m = state.coach_stats.get("rec_marks", {}).get(r["id"])
    r["status"], r["status_at"], r["snoozed_until"] = "open", None, None
    if not m:
        return
    if m["status"] == "snoozed":
        until = m.get("until") or ""
        if until <= datetime.now().isoformat(timespec="seconds"):
            return
        r["snoozed_until"] = until
    r["status"] = m["status"]
    r["status_at"] = m.get("at")


def set_rec_status(rec_id: str, status: str, days: int = 7) -> dict:
    """Mark a recommendation done, dismissed, snoozed for ``days``, or open
    again. Marks are kept by id, so the same advice coming back on a later
    day keeps its status."""
    marks = state.coach_stats.setdefault("rec_marks", {})
    now = datetime.now()
    if status == "open":
        marks.pop(rec_id, None)
        return {"id": rec_id, "status": "open"}
    if status not in REC_STATUSES:
        raise ValueError(f"unknown status {status!r}")
    mark = {"status": status, "at": now.isoformat(timespec="seconds")}
    if status == "snoozed":
        days = max(1, min(int(days), SNOOZE_DAYS_MAX))
        mark["until"] = (now + timedelta(days=days)).isoformat(timespec="seconds")
    marks[rec_id] = mark
    while len(marks) > MAX_REC_MARKS:
        del marks[min(marks, key=lambda k: marks[k].get("at") or "")]
    return {"id": rec_id, **mark}


# ---------------------------------------------------------------------------
# Subscription capacity
# ---------------------------------------------------------------------------

HOT_UTILIZATION = 0.8  # a window at or above this is close to its limit
COOL_UTILIZATION = 0.5  # every window at or below this has room to spare
_WINDOW_SEC = {"5h": 5 * 3600, "7d": 7 * 86400, "7d_opus": 7 * 86400, "7d_sonnet": 7 * 86400}
_WINDOW_NAME = {"5h": "5 giờ", "7d": "tuần", "7d_opus": "tuần (Opus)", "7d_sonnet": "tuần (Sonnet)"}


def _live_windows(acct: dict) -> list[dict]:
    """Windows that have not reset since their headers were captured, with
    the share of the window elapsed and a projection to its end."""
    now = datetime.now()
    out = []
    for w in acct["rate_limits"]["unified"]:
        try:
            reset = datetime.fromisoformat(str(w["reset"]))
        except (TypeError, ValueError):
            continue
        left = (reset - now).total_seconds()
        if left <= 0:
            continue
        span = _WINDOW_SEC.get(w["window"])
        elapsed = max(0.0, span - left) / span if span else None
        projected = (
            w["utilization"] / elapsed if elapsed and elapsed > 0.1 and w["utilization"] else None
        )
        out.append({**w, "left_s": left, "elapsed": elapsed, "projected": projected})
    return out


def _fmt_left(seconds: float) -> str:
    if seconds < 3600:
        return f"{round(seconds / 60)} phút"
    if seconds < 86400:
        return f"{seconds / 3600:.0f} giờ"
    return f"{seconds / 86400:.1f} ngày"


def capacity_recommendations() -> list[dict]:
    """Balance members across the Claude subscriptions behind the proxy: an
    account near (or projected past) its limit next to one with room."""
    recs: list[dict] = []
    accts = [a for a in accounts_view() if a["rate_limits"]["unified"]]
    if not accts:
        return recs
    state_of = {}
    for a in accts:
        live = _live_windows(a)
        peak = max(live, key=lambda w: w["utilization"], default=None)
        weekly = [w for w in live if w["window"].startswith("7d")]
        over_pace = [w for w in weekly if (w["projected"] or 0) >= 1.0]
        state_of[a["id"]] = {
            "live": live,
            "peak": peak,
            "hot": bool(peak and peak["utilization"] >= HOT_UTILIZATION) or bool(over_pace),
            "over_pace": over_pace,
            "cool": bool(live) and all(w["utilization"] <= COOL_UTILIZATION for w in live),
        }
    cool = sorted(
        (a for a in accts if state_of[a["id"]]["cool"]),
        key=lambda a: max(w["utilization"] for w in state_of[a["id"]]["live"]),
    )
    hot = [a for a in accts if state_of[a["id"]]["hot"]]
    for a in hot:
        st = state_of[a["id"]]
        peak = st["peak"]
        pace = st["over_pace"][0] if st["over_pace"] else None
        w = peak if peak["utilization"] >= HOT_UTILIZATION else pace
        name = _WINDOW_NAME.get(w["window"], w["window"])
        members = [m for m in a["members"] if m["user"] != "(unlabeled)"]
        total = sum(m["cost_usd"] or 0 for m in members) or sum(m["requests"] for m in members)

        def share(m: dict, total: float = total) -> float:
            v = m["cost_usd"] if m["cost_usd"] is not None else m["requests"]
            return v / total if total else 0.0

        heavy = [m for m in members if share(m) >= 0.15][:3]
        evidence = [
            {"label": f"Cửa sổ {name}", "value": f"{round(w['utilization'] * 100)}% đã dùng"},
            {"label": "Reset sau", "value": _fmt_left(w["left_s"])},
        ]
        if w.get("projected") and w["projected"] >= 1.0:
            evidence.append(
                {"label": "Dự báo cuối kỳ", "value": f"{round(min(w['projected'], 9.99) * 100)}%"}
            )
        evidence += [
            {"label": m["user"], "value": f"{round(share(m) * 100)}% mức dùng"} for m in heavy
        ]
        critical = w["utilization"] >= 0.95 or a["rate_limits"]["unified_status"] == "rejected"
        target = cool[0] if cool and cool[0]["id"] != a["id"] else None
        movers = ", ".join(m["user"] for m in heavy) or "một vài thành viên"
        if target:
            tw = max(state_of[target["id"]]["live"], key=lambda x: x["utilization"])
            evidence.append(
                {
                    "label": f"{target['label']} (còn trống)",
                    "value": f"{round(tw['utilization'] * 100)}% đã dùng",
                }
            )
            title = f"{a['label']}: cửa sổ {name} {round(w['utilization'] * 100)}% — chuyển bớt sang {target['label']}"
            detail = (
                f"{a['label']} sắp chạm giới hạn {name} (reset sau {_fmt_left(w['left_s'])}), trong khi "
                f"{target['label']} mới dùng {round(tw['utilization'] * 100)}%. Chuyển {movers} sang "
                f"{target['label']} để không ai bị chặn giữa phiên."
            )
            actions = [
                f"Yêu cầu {movers} đăng nhập lại Claude Code bằng {target['label']} (/login).",
                f"Theo dõi panel Rate limits: {a['label']} nên giảm dưới {round(HOT_UTILIZATION * 100)}%.",
                "Cập nhật ACCOUNT_LABELS nếu subscription chưa có tên dễ nhận biết.",
            ]
        else:
            title = f"{a['label']}: cửa sổ {name} {round(w['utilization'] * 100)}%, không còn subscription trống"
            detail = (
                f"{a['label']} sắp chạm giới hạn {name} và không subscription nào khác còn dưới "
                f"{round(COOL_UTILIZATION * 100)}%. Giãn việc nặng sang sau khi reset "
                f"({_fmt_left(w['left_s'])}) hoặc cân nhắc thêm subscription."
            )
            actions = [
                f"Ưu tiên việc quan trọng; dời việc nặng sang sau khi reset ({_fmt_left(w['left_s'])}).",
                f"Chuyển {movers} sang model rẻ hơn (Sonnet) cho việc thường ngày.",
                "Nếu tình trạng lặp lại hàng tuần, cân nhắc thêm một subscription.",
            ]
        recs.append(
            {
                "kind": "capacity",
                "severity": "warn",
                "priority": "high" if critical else "medium",
                "scope": "subscription",
                "target": a["label"],
                "title": title,
                "detail": detail,
                "savings_usd": None,
                "savings_window": None,
                "evidence": evidence,
                "actions": actions,
                "effort": "low" if target else "medium",
                "confidence": "high" if w["utilization"] >= HOT_UTILIZATION else "medium",
            }
        )
    return recs


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
        # Whether the 1h cache TTL pays for itself this period.
        "cache_ttl": cache_ttl_view(),
    }
