"""Quota counter persistence, monthly reset, and bucket eviction."""

from __future__ import annotations

import json
import os
import time
from datetime import datetime

from .. import settings, state
from ..terminal import RESET, YELLOW, log


def _load_quota_stats() -> bool:
    """Load persisted quota counters from disk into quota_stats.

    Returns True if a file was loaded, False otherwise. Bad files are
    skipped silently — corrupt persistence shouldn't break the proxy.
    """
    if not settings.QUOTA_TRACKING_ENABLED:
        return False
    if not os.path.exists(settings.QUOTA_PERSIST_PATH):
        return False
    try:
        with open(settings.QUOTA_PERSIST_PATH, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return False
    if not isinstance(data, dict):
        return False
    version = data.get("version")
    if (
        not isinstance(version, int)
        or version < settings.QUOTA_SCHEMA_MIN_LOAD
        or version > settings.QUOTA_SCHEMA_VERSION
    ):
        return False

    ut = data.get("usage_total")
    if isinstance(ut, dict):
        for k in state.quota_stats["usage_total"]:
            v = ut.get(k, 0)
            if isinstance(v, int):
                state.quota_stats["usage_total"][k] = v

    if isinstance(data.get("cost_usd_total"), (int, float)):
        state.quota_stats["cost_usd_total"] = float(data["cost_usd_total"])
    if isinstance(data.get("messages_requests"), int):
        state.quota_stats["messages_requests"] = data["messages_requests"]
    if isinstance(data.get("last_request_at"), str):
        state.quota_stats["last_request_at"] = data["last_request_at"]

    bm = data.get("by_model")
    if isinstance(bm, dict):
        for model_key, bucket in bm.items():
            if isinstance(bucket, dict) and "model" in bucket:
                state.quota_stats["by_model"][model_key] = bucket

    # v2 fields — absent in v1 files, default to empty dicts.
    bs = data.get("by_session")
    if isinstance(bs, dict):
        for sid, bucket in bs.items():
            if isinstance(bucket, dict) and "session_id" in bucket:
                state.quota_stats["by_session"][sid] = bucket

    bd = data.get("by_day")
    if isinstance(bd, dict):
        for day, bucket in bd.items():
            if isinstance(bucket, dict) and "date" in bucket:
                state.quota_stats["by_day"][day] = bucket

    if isinstance(data.get("period_month"), str):
        state.quota_stats["period_month"] = data["period_month"]

    # v3 — per-user buckets (absent in v1/v2, default empty).
    bu = data.get("by_user")
    if isinstance(bu, dict):
        for label, bucket in bu.items():
            if isinstance(bucket, dict) and "label" in bucket:
                # v4 backfill: older v3 buckets won't have the models sub-dict.
                if "models" not in bucket or not isinstance(bucket.get("models"), dict):
                    bucket["models"] = {}
                state.quota_stats["by_user"][label] = bucket

    # v4 — per-day per-user buckets.
    bdu = data.get("by_day_user")
    if isinstance(bdu, dict):
        for date_str, by_label in bdu.items():
            if not isinstance(by_label, dict):
                continue
            cleaned = {}
            for label, entry in by_label.items():
                if isinstance(entry, dict):
                    cleaned[label] = entry
            if cleaned:
                state.quota_stats["by_day_user"][date_str] = cleaned

    _check_monthly_reset()
    return True


def _save_quota_stats(force: bool = False) -> None:
    """Atomically persist quota counters to disk.

    Debounced: skipped if last write was less than
    QUOTA_PERSIST_INTERVAL_SECONDS ago, unless force=True.
    """
    if not settings.QUOTA_TRACKING_ENABLED:
        return
    now = time.monotonic()
    if (
        not force
        and now - state.runtime.last_quota_save_at < settings.QUOTA_PERSIST_INTERVAL_SECONDS
    ):
        return

    payload = {
        "version": settings.QUOTA_SCHEMA_VERSION,
        "saved_at": datetime.now().isoformat(timespec="seconds"),
        "messages_requests": state.quota_stats["messages_requests"],
        "last_request_at": state.quota_stats["last_request_at"],
        "usage_total": state.quota_stats["usage_total"],
        "cost_usd_total": state.quota_stats["cost_usd_total"],
        "by_model": state.quota_stats["by_model"],
        "by_session": state.quota_stats["by_session"],
        "by_day": state.quota_stats["by_day"],
        "by_day_user": state.quota_stats["by_day_user"],
        "by_user": state.quota_stats["by_user"],
        "period_month": state.quota_stats["period_month"],
    }
    tmp_path = settings.QUOTA_PERSIST_PATH + ".tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        os.replace(tmp_path, settings.QUOTA_PERSIST_PATH)
        state.runtime.last_quota_save_at = now
    except OSError:
        # Disk full / permission issue — skip silently, try again next time.
        pass


def _check_monthly_reset() -> None:
    """Auto-reset period totals when the calendar month rolls over.

    by_day history is always kept so the trend chart stays intact.
    Only cost_usd_total, usage_total, by_model, and by_session are cleared.
    """
    if not settings.QUOTA_TRACKING_ENABLED or not settings.QUOTA_MONTHLY_RESET:
        return
    current_month = datetime.now().strftime("%Y-%m")
    period = state.quota_stats["period_month"]
    if period and period != current_month:
        log(
            f"{YELLOW}Monthly reset: {period} → {current_month} "
            f"(previous: ${state.quota_stats['cost_usd_total']:.4f} / "
            f"{state.quota_stats['messages_requests']} reqs){RESET}"
        )
        for k in state.quota_stats["usage_total"]:
            state.quota_stats["usage_total"][k] = 0
        state.quota_stats["cost_usd_total"] = 0.0
        state.quota_stats["messages_requests"] = 0
        state.quota_stats["last_request_at"] = None
        state.quota_stats["by_model"] = {}
        state.quota_stats["by_session"] = {}
        # by_day kept intentionally — dashboard trend chart spans multiple months
        _save_quota_stats(force=True)
    state.quota_stats["period_month"] = current_month


def _evict_by_day_user_to_match_by_day() -> None:
    """Keep by_day_user's date set ⊆ by_day's date set.

    by_day is the canonical date list (eviction-capped via _evict_oldest);
    by_day_user just adds the user dimension, so we drop any date that's
    no longer present in by_day to avoid orphan stats.
    """
    valid = set(state.quota_stats["by_day"].keys())
    for d in list(state.quota_stats["by_day_user"].keys()):
        if d not in valid:
            del state.quota_stats["by_day_user"][d]


def _evict_oldest(field: str, sort_key: str, max_entries: int) -> None:
    """Drop oldest entries from quota_stats[field] when over max_entries.

    `sort_key` is the bucket field used to determine age (date string or
    ISO timestamp — both sort lexicographically).
    """
    bucket = state.quota_stats[field]
    if len(bucket) <= max_entries:
        return
    items = sorted(bucket.items(), key=lambda kv: kv[1].get(sort_key, ""))
    drop = len(bucket) - max_entries
    for key, _ in items[:drop]:
        del bucket[key]
