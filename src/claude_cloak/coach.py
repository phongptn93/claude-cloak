"""Coding coach: privacy-safe usage counters derived from proxied traffic."""

from __future__ import annotations

import json
import os
import time
from datetime import datetime

from . import settings, state
from .constants import COACH_EDIT_TOOLS, COACH_READ_TOOLS


def _coach_record_request(body: bytes, content_type: str | None, path: str) -> None:
    """Extract privacy-safe coaching signals from a /v1/messages request.

    Inspects ONLY tool_result blocks in the last message (messages[-1]) —
    the outcomes of the previous assistant turn — to measure tool
    reliability / error rate. Prompt content is never read or evaluated.
    Counts only; no text, code or file paths are ever stored. Never raises.
    """
    if not settings.COACH_ENABLED or "v1/messages" not in path:
        return
    if not content_type or "json" not in content_type.lower():
        return
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError, ValueError):
        return
    if not isinstance(data, dict):
        return
    messages = data.get("messages")
    if not isinstance(messages, list) or not messages:
        return
    last = messages[-1]
    if not isinstance(last, dict) or last.get("role") != "user":
        return
    content = last.get("content")
    if not isinstance(content, list):
        return

    n_results = 0
    n_errors = 0
    for block in content:
        if not isinstance(block, dict) or block.get("type") != "tool_result":
            continue
        n_results += 1
        if block.get("is_error") is True:
            n_errors += 1

    state.coach_stats["tool_results_seen"] += n_results
    state.coach_stats["tool_errors"] += n_errors


def _coach_record_response(tools_used: dict, stop_reason: str | None) -> None:
    """Record one assistant turn's tool calls + stop reason. Never raises."""
    if not settings.COACH_ENABLED:
        return
    now = datetime.now()
    iso = now.isoformat(timespec="seconds")
    state.coach_stats["assistant_turns"] += 1
    if state.coach_stats["first_seen"] is None:
        state.coach_stats["first_seen"] = iso
    state.coach_stats["last_seen"] = iso
    hour = str(now.hour)
    state.coach_stats["by_hour"][hour] = state.coach_stats["by_hour"].get(hour, 0) + 1
    if tools_used:
        for name, n in tools_used.items():
            state.coach_stats["tools"][name] = state.coach_stats["tools"].get(name, 0) + (n or 0)
    if stop_reason:
        state.coach_stats["stop_reasons"][stop_reason] = (
            state.coach_stats["stop_reasons"].get(stop_reason, 0) + 1
        )
    _save_coach_stats()


def _load_coach_stats() -> bool:
    """Load persisted coaching counters from .coach.json. Bad files skipped."""
    if not settings.COACH_ENABLED or not os.path.exists(settings.COACH_PERSIST_PATH):
        return False
    try:
        with open(settings.COACH_PERSIST_PATH, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return False
    if not isinstance(data, dict):
        return False
    version = data.get("version")
    if not isinstance(version, int) or version < 1 or version > settings.COACH_SCHEMA_VERSION:
        return False

    for key in ("tools", "stop_reasons", "by_hour"):
        v = data.get(key)
        if isinstance(v, dict):
            state.coach_stats[key] = {
                str(k): int(x) for k, x in v.items() if isinstance(x, (int, float))
            }
    for key in ("tool_results_seen", "tool_errors", "assistant_turns"):
        v = data.get(key)
        if isinstance(v, int):
            state.coach_stats[key] = v
    for key in ("first_seen", "last_seen"):
        v = data.get(key)
        if isinstance(v, str):
            state.coach_stats[key] = v
    return True


def _save_coach_stats(force: bool = False) -> None:
    """Atomically persist coaching counters. Debounced like quota stats."""
    if not settings.COACH_ENABLED:
        return
    now = time.monotonic()
    if (
        not force
        and now - state.runtime.last_coach_save_at < settings.QUOTA_PERSIST_INTERVAL_SECONDS
    ):
        return
    payload = {
        "version": settings.COACH_SCHEMA_VERSION,
        "saved_at": datetime.now().isoformat(timespec="seconds"),
    }
    payload.update(state.coach_stats)
    tmp_path = settings.COACH_PERSIST_PATH + ".tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        os.replace(tmp_path, settings.COACH_PERSIST_PATH)
        state.runtime.last_coach_save_at = now
    except OSError:
        pass


def _compute_coach_view() -> dict:
    """Derive the dashboard-facing coaching metrics, score and tips.

    Reuses quota_stats for cache/model/session signals so nothing extra is
    collected. Returns plain JSON-able data; all scores are 0-100 where
    higher is better. Components with no data are omitted from the average.
    """
    tools = state.coach_stats["tools"]
    reads = sum(n for t, n in tools.items() if t in COACH_READ_TOOLS)
    edits = sum(n for t, n in tools.items() if t in COACH_EDIT_TOOLS)
    tool_total = sum(tools.values())

    results_seen = state.coach_stats["tool_results_seen"]
    errors = state.coach_stats["tool_errors"]
    error_rate = (errors / results_seen) if results_seen else 0.0

    # Cache hit rate from the existing quota totals (input that was served
    # from cache instead of paid fresh).
    ut = state.quota_stats["usage_total"]
    paid_in = ut.get("input_tokens", 0) or 0
    cache_read = ut.get("cache_read_input_tokens", 0) or 0
    cache_denom = paid_in + cache_read
    cache_hit_rate = (cache_read / cache_denom) if cache_denom else 0.0

    # Conversation depth: requests per distinct session (≈ turns / session).
    sessions = state.quota_stats["by_session"]
    total_reqs = sum(s.get("requests", 0) for s in sessions.values())
    avg_turns = (total_reqs / len(sessions)) if sessions else 0.0

    # Model fit: share of spend on the priciest "opus" tier.
    by_model = state.quota_stats["by_model"]
    total_cost = sum(m.get("cost_usd", 0.0) for m in by_model.values()) or 0.0
    opus_cost = sum(m.get("cost_usd", 0.0) for k, m in by_model.items() if "opus" in k.lower())
    opus_share = (opus_cost / total_cost) if total_cost else 0.0

    # ---- component scores (0-100, higher = better) ----
    components: dict[str, float] = {}
    if edits > 0:
        # One read per edit == full marks; fewer reads scales down.
        components["discipline"] = max(0.0, min(100.0, (reads / edits) * 100.0))
    if results_seen > 0:
        components["reliability"] = max(0.0, (1.0 - error_rate) * 100.0)
    if cache_denom > 0:
        # CC keeps a high hit rate; treat ~85% as full marks.
        components["cache"] = max(0.0, min(100.0, (cache_hit_rate / 0.85) * 100.0))

    weights = {"discipline": 0.40, "reliability": 0.35, "cache": 0.25}
    wsum = sum(weights[k] for k in components)
    score = round(sum(components[k] * weights[k] for k in components) / wsum) if wsum else None

    # ---- actionable tips (Vietnamese, local, no content) ----
    tips: list[str] = []
    if edits > 0 and reads < edits:
        tips.append(
            f"Bạn sửa file nhiều hơn đọc ({reads} Read / {edits} Edit-Write). "
            "Đọc trước khi sửa để tránh ghi đè nhầm."
        )
    if results_seen > 0 and error_rate > 0.15:
        tips.append(
            f"{int(error_rate * 100)}% tool call bị lỗi. "
            "Kiểm tra lệnh/đường dẫn trước khi chạy để đỡ tốn lượt."
        )
    if cache_denom > 0 and cache_hit_rate < 0.5:
        tips.append(
            f"Cache hit thấp ({int(cache_hit_rate * 100)}%). "
            "Tránh đổi context liên tục để tận dụng cache — tiết kiệm tiền."
        )
    if total_cost > 0 and opus_share > 0.8:
        tips.append(
            f"{int(opus_share * 100)}% chi phí nằm trên Opus. "
            "Cân nhắc Sonnet/Haiku cho việc đơn giản để giảm chi phí."
        )
    if score is not None and not tips:
        tips.append("Phong độ tốt — không có cảnh báo nào. Giữ vững!")
    if score is None:
        tips.append("Chưa đủ dữ liệu. Dùng Claude Code qua proxy một lúc để có insight.")

    return {
        "enabled": settings.COACH_ENABLED,
        "score": score,
        "components": {k: round(v) for k, v in components.items()},
        "assistant_turns": state.coach_stats["assistant_turns"],
        "tools": dict(sorted(tools.items(), key=lambda kv: kv[1], reverse=True)),
        "tool_total": tool_total,
        "reads": reads,
        "edits": edits,
        "tool_results_seen": results_seen,
        "tool_errors": errors,
        "error_rate": round(error_rate, 4),
        "cache_hit_rate": round(cache_hit_rate, 4),
        "avg_turns_per_session": round(avg_turns, 1),
        "opus_cost_share": round(opus_share, 4),
        "stop_reasons": dict(state.coach_stats["stop_reasons"]),
        "by_hour": [state.coach_stats["by_hour"].get(str(h), 0) for h in range(24)],
        "first_seen": state.coach_stats["first_seen"],
        "last_seen": state.coach_stats["last_seen"],
        "tips": tips,
    }
