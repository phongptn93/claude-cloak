"""Optional Grafana Loki log shipping."""

from __future__ import annotations

import asyncio
import json
import time

from . import settings, state
from .terminal import RESET, YELLOW, log


def _build_loki_labels(extra: dict | None = None) -> dict:
    """Assemble the label set for one Loki stream.

    Loki indexes by label set, so keep cardinality low — only `model`
    and `event` vary per request.
    """
    labels = {"job": settings.LOKI_JOB, "host": settings.LOKI_HOST}
    if settings.LOKI_USER_EMAIL:
        labels["user_email"] = settings.LOKI_USER_EMAIL
    if settings.LOKI_EXTRA_LABELS:
        labels.update(settings.LOKI_EXTRA_LABELS)
    if extra:
        for k, v in extra.items():
            if v is None or v == "":
                continue
            labels[k] = str(v)
    return labels


def _loki_enqueue(event: str, fields: dict | None = None, model: str | None = None) -> None:
    """Append a structured event to the Loki send buffer.

    No-op when LOKI_URL is unset. Drops the oldest entry once the buffer
    cap is hit to bound memory usage when Loki is unreachable.
    """
    if not settings.LOKI_ENABLED:
        return
    if len(state.loki_buffer) >= settings.LOKI_MAX_BUFFER:
        state.loki_buffer.pop(0)
        state.runtime.loki_dropped_count += 1
    extra_labels: dict[str, str] = {"event": event}
    if model:
        extra_labels["model"] = model
    labels = _build_loki_labels(extra_labels)
    payload: dict = {"event": event}
    if model:
        payload["model"] = model
    if fields:
        for k, v in fields.items():
            if v is None:
                continue
            payload[k] = v
    ts_ns = str(time.time_ns())
    state.loki_buffer.append((ts_ns, labels, payload))


async def _loki_flush_once() -> bool:
    """Push up to LOKI_BATCH_SIZE entries to Loki. Returns True on success."""
    if not state.loki_buffer or state.runtime.telemetry_client is None:
        return True
    batch_size = min(len(state.loki_buffer), settings.LOKI_BATCH_SIZE)
    batch = state.loki_buffer[:batch_size]

    # Loki streams are keyed by label set, so group entries that share labels.
    streams_map: dict[tuple, list[list[str]]] = {}
    for ts, labels, fields in batch:
        key = tuple(sorted(labels.items()))
        line = json.dumps(fields, ensure_ascii=False, separators=(",", ":"))
        streams_map.setdefault(key, []).append([ts, line])

    payload = {
        "streams": [{"stream": dict(key), "values": values} for key, values in streams_map.items()]
    }
    try:
        r = await state.runtime.telemetry_client.post(
            settings.LOKI_URL, json=payload, timeout=settings.LOKI_TIMEOUT_SECONDS
        )
        if r.status_code >= 400:
            raise RuntimeError(f"Loki returned {r.status_code}: {r.text[:200]}")
        del state.loki_buffer[:batch_size]
        return True
    except Exception as e:
        now_ = time.monotonic()
        if now_ - state.runtime.loki_last_warn_at > 60:
            log(f"  {YELLOW}Loki push failed: {e}{RESET}")
            state.runtime.loki_last_warn_at = now_
        return False


async def _loki_flusher_loop() -> None:
    """Background task: flushes the buffer at LOKI_FLUSH_INTERVAL_SECONDS."""
    while True:
        try:
            await asyncio.sleep(settings.LOKI_FLUSH_INTERVAL_SECONDS)
            await _loki_flush_once()
        except asyncio.CancelledError:
            raise
        except Exception:
            # Never let a stray exception kill the flusher.
            pass
