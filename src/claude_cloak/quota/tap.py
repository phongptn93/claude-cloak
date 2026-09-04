"""Streaming/non-streaming usage extractor wrapped around upstream responses."""

from __future__ import annotations

import json

from .. import settings


class UsageTap:
    """Tap a /v1/messages response stream to extract `usage` and `model`.

    Handles both:
      - Streaming SSE: parses `data: {...}` lines for message_start/message_delta
        events incrementally, discarding parsed bytes to keep memory bounded.
      - Non-streaming JSON: buffers full body (small for /v1/messages — typically
        <100 KB) and parses at finalize() time.

    Bytes are NEVER mutated — feed() inspects, the proxy still forwards the
    untouched chunk to the client. A 5 MB safety cap prevents runaway buffers.
    """

    def __init__(
        self,
        content_type: str | None,
        path: str,
        session_id: str | None = None,
        user_label: str | None = None,
    ):
        self.path = path
        self.session_id = session_id
        self.user_label = user_label
        self.is_messages = "v1/messages" in path
        ct = (content_type or "").lower()
        self.is_sse = "event-stream" in ct
        self.is_json = "json" in ct and not self.is_sse
        self.buffer = bytearray()
        self.usage: dict = {}
        self.model: str | None = None
        self.cache_creation: dict | None = None
        self._overflow = False
        # Coaching signals (counts only — see coach_stats).
        self.tools_used: dict[str, int] = {}
        self.stop_reason: str | None = None

    def feed(self, chunk: bytes) -> None:
        if not self.is_messages or not chunk or self._overflow:
            return
        if len(self.buffer) + len(chunk) > settings.USAGE_TAP_MAX_BUFFER:
            self._overflow = True
            self.buffer.clear()
            return
        self.buffer.extend(chunk)
        if self.is_sse:
            self._drain_sse_lines()

    def _drain_sse_lines(self) -> None:
        while True:
            nl = self.buffer.find(b"\n")
            if nl < 0:
                return
            line = bytes(self.buffer[:nl]).rstrip(b"\r")
            del self.buffer[: nl + 1]
            if not line.startswith(b"data: "):
                continue
            payload = line[6:]
            if payload == b"[DONE]":
                continue
            try:
                event = json.loads(payload)
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            if isinstance(event, dict):
                self._absorb_event(event)

    def _absorb_event(self, event: dict) -> None:
        t = event.get("type")
        if t == "message_start":
            msg = event.get("message", {})
            if isinstance(msg, dict):
                self.model = msg.get("model") or self.model
                u = msg.get("usage")
                if isinstance(u, dict):
                    self._merge_usage(u)
        elif t == "message_delta":
            u = event.get("usage")
            if isinstance(u, dict):
                self._merge_usage(u)
            delta = event.get("delta")
            if isinstance(delta, dict) and delta.get("stop_reason"):
                self.stop_reason = delta["stop_reason"]
        elif t == "content_block_start":
            cb = event.get("content_block")
            if isinstance(cb, dict) and cb.get("type") == "tool_use":
                name = cb.get("name") or "unknown"
                self.tools_used[name] = self.tools_used.get(name, 0) + 1

    def _merge_usage(self, u: dict) -> None:
        for k in (
            "input_tokens",
            "output_tokens",
            "cache_creation_input_tokens",
            "cache_read_input_tokens",
        ):
            if k in u and u[k] is not None:
                self.usage[k] = u[k]
        cc = u.get("cache_creation")
        if isinstance(cc, dict):
            self.cache_creation = cc

    def finalize(self) -> tuple[str | None, dict]:
        if not self.is_messages:
            return None, {}
        if self.is_json and self.buffer and not self._overflow:
            try:
                data = json.loads(bytes(self.buffer))
            except (json.JSONDecodeError, UnicodeDecodeError):
                data = None
            if isinstance(data, dict):
                self.model = data.get("model") or self.model
                u = data.get("usage")
                if isinstance(u, dict):
                    self._merge_usage(u)
                if data.get("stop_reason"):
                    self.stop_reason = data["stop_reason"]
                blocks = data.get("content")
                if isinstance(blocks, list):
                    for cb in blocks:
                        if isinstance(cb, dict) and cb.get("type") == "tool_use":
                            name = cb.get("name") or "unknown"
                            self.tools_used[name] = self.tools_used.get(name, 0) + 1
        if self.cache_creation is not None:
            self.usage["cache_creation"] = self.cache_creation
        # Free the buffer; we're done with it.
        self.buffer.clear()
        return self.model, dict(self.usage)

    def coach_signals(self) -> tuple[dict, str | None]:
        """Return (tool_use counts, stop_reason) gathered from this response."""
        return dict(self.tools_used), self.stop_reason
