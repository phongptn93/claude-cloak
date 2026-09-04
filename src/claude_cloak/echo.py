"""Development echo upstream.

With ``DEV_ECHO_MODE=true`` the proxy answers ``/v1/*`` itself instead of
calling any upstream, returning an Anthropic-shaped response (SSE when the
request asked to stream). Everything before the network hop — identity locking,
body sanitization, token saver, usage/cost recording, coach counters — runs
exactly as in live mode, so the pipeline can be exercised offline.

Never enable this in production: no request reaches Anthropic.
"""

from __future__ import annotations

import json
import time
import uuid

from . import settings


def wants_echo(path: str) -> bool:
    return settings.DEV_ECHO_MODE


def _usage() -> dict:
    usage = {
        "input_tokens": settings.DEV_ECHO_INPUT_TOKENS,
        "output_tokens": settings.DEV_ECHO_OUTPUT_TOKENS,
    }
    if settings.DEV_ECHO_CACHE_READ_TOKENS:
        usage["cache_read_input_tokens"] = settings.DEV_ECHO_CACHE_READ_TOKENS
    if settings.DEV_ECHO_CACHE_WRITE_TOKENS:
        usage["cache_creation_input_tokens"] = settings.DEV_ECHO_CACHE_WRITE_TOKENS
    return usage


def _request_summary(method: str, path: str, headers: dict, body: bytes) -> dict:
    """Counts and shapes only — never the prompt text itself."""
    summary = {
        "method": method,
        "path": "/" + path,
        "body_bytes": len(body),
        "header_count": len(headers),
    }
    try:
        data = json.loads(body or b"{}")
    except (ValueError, TypeError):
        return summary
    if isinstance(data, dict):
        summary["model_requested"] = data.get("model")
        summary["stream"] = bool(data.get("stream"))
        messages = data.get("messages")
        if isinstance(messages, list):
            summary["message_count"] = len(messages)
        tools = data.get("tools")
        if isinstance(tools, list):
            summary["tool_count"] = len(tools)
    return summary


def is_streaming_request(body: bytes) -> bool:
    try:
        data = json.loads(body or b"{}")
    except (ValueError, TypeError):
        return False
    return isinstance(data, dict) and bool(data.get("stream"))


def echo_response(method: str, path: str, headers: dict, body: bytes) -> tuple[bytes, str]:
    """Return ``(payload, content_type)`` for a non-streaming echo reply."""
    summary = _request_summary(method, path, headers, body)
    payload = {
        "id": f"msg_echo_{uuid.uuid4().hex[:16]}",
        "type": "message",
        "role": "assistant",
        "model": settings.DEV_ECHO_MODEL,
        "content": [
            {
                "type": "text",
                "text": "claude-cloak DEV_ECHO_MODE: request was not forwarded upstream.\n"
                + json.dumps(summary, indent=2, sort_keys=True),
            }
        ],
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": _usage(),
        "_claude_cloak_echo": summary,
    }
    return json.dumps(payload).encode(), "application/json"


def echo_sse_events(method: str, path: str, headers: dict, body: bytes) -> list[bytes]:
    """Anthropic-shaped SSE frames for a streaming echo reply."""
    summary = _request_summary(method, path, headers, body)
    message_id = f"msg_echo_{uuid.uuid4().hex[:16]}"
    text = "claude-cloak DEV_ECHO_MODE: request was not forwarded upstream."
    usage = _usage()

    def frame(event: str, data: dict) -> bytes:
        return f"event: {event}\ndata: {json.dumps(data)}\n\n".encode()

    return [
        frame(
            "message_start",
            {
                "type": "message_start",
                "message": {
                    "id": message_id,
                    "type": "message",
                    "role": "assistant",
                    "model": settings.DEV_ECHO_MODEL,
                    "content": [],
                    "stop_reason": None,
                    "usage": {**usage, "output_tokens": 0},
                },
            },
        ),
        frame(
            "content_block_start",
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""},
            },
        ),
        frame(
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": text},
            },
        ),
        frame(
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": " " + json.dumps(summary, sort_keys=True)},
            },
        ),
        frame("content_block_stop", {"type": "content_block_stop", "index": 0}),
        frame(
            "message_delta",
            {
                "type": "message_delta",
                "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                "usage": {"output_tokens": usage["output_tokens"]},
            },
        ),
        frame("message_stop", {"type": "message_stop"}),
    ]


async def echo_delay() -> None:
    if settings.DEV_ECHO_LATENCY_MS > 0:
        import asyncio

        await asyncio.sleep(settings.DEV_ECHO_LATENCY_MS / 1000.0)


def echo_started_at() -> float:
    return time.monotonic()
