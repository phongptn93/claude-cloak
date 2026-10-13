"""Is the 1-hour prompt-cache TTL paying for itself?

A 1h cache write costs 2x input instead of 1.25x. It only pays back when a
conversation pauses for 5-60 minutes: a 5-minute entry would have expired and
the next turn would re-write the whole prefix, while the 1h entry is still
read at the cache-read rate. So for every response this tracks:

- premium: 1h write tokens x (1h write rate - 5m write rate)
- saved:   cache-read tokens on a turn that followed a 5-60 minute pause in
           the same session and model, x (5m write rate - cache-read rate)

Pauses are measured per (session, model). Subagents share their parent's
session id, so interleaved calls can make pauses look shorter than they
were; "saved" therefore errs low.
"""

from __future__ import annotations

import time
from collections import OrderedDict

from .. import state
from ..pricing import rates_for

FIVE_MIN = 300
ONE_HOUR = 3600
_MAX_TRACKED = 5000
_last_turn: OrderedDict[tuple[str, str], float] = OrderedDict()


def empty_stats() -> dict:
    return {
        "requests_client_1h": 0,  # the client asked for the 1h TTL itself
        "gaps": {"under_5m": 0, "5m_to_1h": 0, "over_1h": 0},
        "premium_usd": 0.0,
        "saved_usd": 0.0,
    }


def _stats() -> dict:
    s = state.quota_stats.get("cache_ttl")
    if not isinstance(s, dict):
        s = state.quota_stats["cache_ttl"] = empty_stats()
    return s


def _asks_for_1h(block) -> bool:
    cc = block.get("cache_control") if isinstance(block, dict) else None
    return isinstance(cc, dict) and cc.get("ttl") == "1h"


def record_client_cache_ttl(data: dict, path: str) -> None:
    """Note whether the client's own request uses the 1h TTL (before the
    token saver touches it). Looks only where cache_control can sit."""
    if "v1/messages" not in path:
        return
    blocks = []
    for field in ("tools", "system"):
        if isinstance(data.get(field), list):
            blocks.extend(data[field])
    for msg in data.get("messages") or []:
        if isinstance(msg, dict) and isinstance(msg.get("content"), list):
            blocks.extend(msg["content"])
    if any(_asks_for_1h(b) for b in blocks):
        _stats()["requests_client_1h"] += 1


def record_cache_ttl_usage(session_id: str | None, model_key: str, usage: dict) -> None:
    s = _stats()
    rates = rates_for(model_key)
    cc = usage.get("cache_creation") if isinstance(usage.get("cache_creation"), dict) else {}
    w1h = cc.get("ephemeral_1h_input_tokens", 0) or 0
    s["premium_usd"] += w1h * (rates["cache_write_1h"] - rates["cache_write_5m"]) / 1e6

    if not session_id:
        return
    now = time.monotonic()
    key = (session_id, model_key)
    last = _last_turn.pop(key, None)
    _last_turn[key] = now
    while len(_last_turn) > _MAX_TRACKED:
        _last_turn.popitem(last=False)
    if last is None:
        return
    gap = now - last
    if gap < FIVE_MIN:
        s["gaps"]["under_5m"] += 1
    elif gap <= ONE_HOUR:
        s["gaps"]["5m_to_1h"] += 1
        read = usage.get("cache_read_input_tokens", 0) or 0
        s["saved_usd"] += read * (rates["cache_write_5m"] - rates["cache_read"]) / 1e6
    else:
        s["gaps"]["over_1h"] += 1


def cache_ttl_view() -> dict:
    s = _stats()
    total_turns = sum(s["gaps"].values())
    return {
        "requests_client_1h": s["requests_client_1h"],
        "requests_proxy_1h": state.token_saver_stats.get("requests_ttl_upgraded", 0),
        "gaps": dict(s["gaps"]),
        "share_5m_to_1h": round(s["gaps"]["5m_to_1h"] / total_turns, 4) if total_turns else None,
        "premium_usd": round(s["premium_usd"], 2),
        "saved_usd": round(s["saved_usd"], 2),
        "net_usd": round(s["saved_usd"] - s["premium_usd"], 2),
    }
