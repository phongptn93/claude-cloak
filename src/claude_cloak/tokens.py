"""Token saver: prompt-cache TTL extension and tool_result truncation."""

from __future__ import annotations

import json

from . import settings, state
from .terminal import BG_YELLOW, BOLD, RESET, YELLOW, log


def optimize_tokens(body: bytes, content_type: str | None, path: str) -> bytes:
    """Apply token-saving transforms to /v1/messages JSON bodies."""
    if not settings.TOKEN_SAVER_ENABLED or not body:
        return body
    if not content_type or "json" not in content_type.lower():
        return body
    if "v1/messages" not in path:
        return body

    try:
        data = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return body
    if not isinstance(data, dict):
        return body

    original_size = len(body)
    breakpoints = 0
    skipped_full = 0
    truncated = 0

    if settings.CACHE_EXTEND_TTL and not state.runtime.cache_ttl_runtime_disabled:
        breakpoints, skipped_full = _apply_cache_breakpoints(data)
    if settings.TOOL_RESULT_TRUNCATE:
        truncated = _truncate_tool_results(data)

    if breakpoints == 0 and truncated == 0:
        if skipped_full:
            state.token_saver_stats["cache_breakpoints_skipped_full"] += skipped_full
        return body

    new_body = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode()
    saved_bytes = max(0, original_size - len(new_body))

    state.token_saver_stats["requests_optimized"] += 1
    state.token_saver_stats["cache_breakpoints_added"] += breakpoints
    state.token_saver_stats["cache_breakpoints_skipped_full"] += skipped_full
    state.token_saver_stats["tool_results_truncated"] += truncated
    state.token_saver_stats["bytes_saved"] += saved_bytes
    state.token_saver_stats["tokens_saved_est"] += saved_bytes // settings.CHARS_PER_TOKEN

    return new_body


def _count_cache_breakpoints(data: dict) -> int:
    """Count existing cache_control occurrences across system, tools, messages."""
    count = 0

    def visit(node):
        nonlocal count
        if isinstance(node, dict):
            if "cache_control" in node:
                count += 1
            for v in node.values():
                visit(v)
        elif isinstance(node, list):
            for item in node:
                visit(item)

    for field in ("system", "tools", "messages"):
        if field in data:
            visit(data[field])
    return count


def _apply_cache_breakpoints(data: dict) -> tuple[int, int]:
    """Bump TTL on the stable prefix to 1h, respecting Anthropic's rules:

    - Processing order: tools → system → messages
    - Once a ttl='1h' block appears, no later ttl='5m' is allowed
    - Max 4 cache_control breakpoints per request

    Strategy: upgrade ALL existing cache_control in tools+system to 1h
    (preserves ordering rule), then optionally add 1 new breakpoint at
    the last tool / last system block if budget permits.
    Messages are left untouched — they sit AFTER system in processing
    order, so messages-5m after system-1h is allowed.

    Returns (modified_count, skipped_full_count).
    """
    existing = _count_cache_breakpoints(data)
    budget = settings.MAX_CACHE_BREAKPOINTS - existing
    modified = 0
    skipped = 0

    # Step 1: upgrade EVERY existing cache_control in tools + system to 1h.
    # This is the critical step that prevents "1h after 5m" violations.
    tools = data.get("tools")
    if isinstance(tools, list):
        for tool in tools:
            if (
                isinstance(tool, dict)
                and isinstance(tool.get("cache_control"), dict)
                and tool["cache_control"].get("ttl") != settings.CACHE_TTL_LONG
            ):
                tool["cache_control"]["ttl"] = settings.CACHE_TTL_LONG
                tool["cache_control"]["type"] = "ephemeral"
                modified += 1

    sys_field = data.get("system")
    if isinstance(sys_field, list):
        for block in sys_field:
            if (
                isinstance(block, dict)
                and isinstance(block.get("cache_control"), dict)
                and block["cache_control"].get("ttl") != settings.CACHE_TTL_LONG
            ):
                block["cache_control"]["ttl"] = settings.CACHE_TTL_LONG
                block["cache_control"]["type"] = "ephemeral"
                modified += 1

    # Step 2: add a new breakpoint at the stable suffix if there isn't one
    # already AND we have budget. Skip silently when full.
    cc_new = {"type": "ephemeral", "ttl": settings.CACHE_TTL_LONG}

    if isinstance(sys_field, str) and sys_field:
        if budget > 0:
            data["system"] = [{"type": "text", "text": sys_field, "cache_control": dict(cc_new)}]
            modified += 1
            budget -= 1
        else:
            skipped += 1
    elif isinstance(sys_field, list) and sys_field:
        last = sys_field[-1]
        if isinstance(last, dict) and "cache_control" not in last:
            if budget > 0:
                last["cache_control"] = dict(cc_new)
                modified += 1
                budget -= 1
            else:
                skipped += 1

    if isinstance(tools, list) and tools:
        last = tools[-1]
        if isinstance(last, dict) and "cache_control" not in last:
            if budget > 0:
                last["cache_control"] = dict(cc_new)
                modified += 1
                budget -= 1
            else:
                skipped += 1

    return modified, skipped


def _head_tail_truncate(text: str) -> str:
    head = text[: settings.TOOL_RESULT_HEAD_BYTES]
    tail = text[-settings.TOOL_RESULT_TAIL_BYTES :] if settings.TOOL_RESULT_TAIL_BYTES > 0 else ""
    omitted = len(text) - len(head) - len(tail)
    marker = f"\n\n[...{omitted} chars truncated by claude-cloak token-saver...]\n\n"
    return head + marker + tail


def _truncate_tool_results(data: dict) -> int:
    """Truncate oversized tool_result blocks in older turns of messages[]."""
    messages = data.get("messages")
    if not isinstance(messages, list):
        return 0

    cutoff = max(0, len(messages) - settings.TOOL_RESULT_KEEP_RECENT)
    truncated = 0

    for msg in messages[:cutoff]:
        if not isinstance(msg, dict):
            continue
        content = msg.get("content")
        if not isinstance(content, list):
            continue
        for block in content:
            if not isinstance(block, dict) or block.get("type") != "tool_result":
                continue
            tc = block.get("content")
            if isinstance(tc, str):
                if len(tc) > settings.TOOL_RESULT_MAX_BYTES:
                    block["content"] = _head_tail_truncate(tc)
                    truncated += 1
            elif isinstance(tc, list):
                for item in tc:
                    if not isinstance(item, dict) or item.get("type") != "text":
                        continue
                    text = item.get("text", "")
                    if isinstance(text, str) and len(text) > settings.TOOL_RESULT_MAX_BYTES:
                        item["text"] = _head_tail_truncate(text)
                        truncated += 1

    return truncated


def inject_cache_ttl_beta(headers: dict[str, str]) -> None:
    """Append the extended-cache-ttl beta to anthropic-beta header (if not present)."""
    if not (settings.TOKEN_SAVER_ENABLED and settings.CACHE_EXTEND_TTL):
        return
    if state.runtime.cache_ttl_runtime_disabled:
        return
    for k in list(headers.keys()):
        if k.lower() == "anthropic-beta":
            existing = headers[k]
            betas = {b.strip() for b in existing.split(",") if b.strip()}
            if settings.CACHE_TTL_BETA not in betas:
                headers[k] = (
                    existing + "," + settings.CACHE_TTL_BETA
                    if existing
                    else settings.CACHE_TTL_BETA
                )
            return
    headers["anthropic-beta"] = settings.CACHE_TTL_BETA


def _looks_like_cache_ttl_beta_error(payload: bytes) -> bool:
    """Detect Anthropic 400 errors caused by the extended-cache-ttl beta
    or any cache_control validation failure (e.g. ordering, ttl shape).
    """
    if not payload:
        return False
    try:
        text = payload.decode("utf-8", errors="replace").lower()
    except Exception:
        return False
    if "extended-cache-ttl" in text:
        return True
    if "anthropic-beta" in text and "invalid" in text:
        return True
    return bool("cache_control" in text and ("ttl" in text or "1h" in text or "5m" in text))


def disable_cache_ttl_runtime(reason: str):
    """Latch off the extended-cache-ttl beta for the rest of the process."""
    if state.runtime.cache_ttl_runtime_disabled:
        return
    state.runtime.cache_ttl_runtime_disabled = True
    state.token_saver_stats["beta_runtime_disabled"] = True
    log("")
    log(
        f"  {BG_YELLOW}{BOLD} TOKEN SAVER FALLBACK {RESET} {YELLOW}cache-ttl 1h disabled: {reason}{RESET}"
    )
    log(f"  {YELLOW}Will use Anthropic default 5m cache for the rest of this session.{RESET}")
    log("")
