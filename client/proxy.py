"""
Claude Cloak Proxy - Maximum anonymity multi-device proxy.

Flow:
  - Máy đầu tiên: login Claude Code → proxy tự bắt TOÀN BỘ identity headers → lưu .env
  - Các máy khác: copy .env → proxy inject identity đã bắt
  - Authorization header: pass-through thẳng từ mỗi request, không lock/lưu

Security Layers:
  1. Header locking - Tất cả device gửi fingerprint giống hệt nhau
  2. Telemetry blocking - Chặn mọi endpoint thu thập thông tin thiết bị
  3. Body sanitization - Xóa machine-identifying fields từ request body
  4. IP header stripping - Xóa headers lộ IP thật (X-Forwarded-For, etc.)
  5. Cookie isolation - Chặn cookie tracking cross-device
  6. Response sanitization - Xóa tracking headers từ response
  7. Request timing jitter - Random delay để mask multi-device patterns
  8. Consistent request IDs - Dùng HMAC-based IDs thay vì random per-device

Token Saver (optional, TOKEN_SAVER=true):
  - Prompt cache 1h TTL: inject cache_control trên system + tools cuối
    (yêu cầu beta header `extended-cache-ttl-2025-04-11`)
  - Tool result truncation: cắt head+tail những tool_result quá lớn
    trong các turn cũ để giảm input token
"""

import asyncio
import hashlib
import hmac
import json
import logging
import os
import random
import re
import secrets
import sys
import time
from contextlib import asynccontextmanager
from datetime import datetime

import httpx
import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse

# Enable ANSI colors on Windows
if sys.platform == "win32":
    os.system("")

ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
load_dotenv(ENV_PATH)

# ============================================================
# ANSI Colors
# ============================================================
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"

BG_GREEN = "\033[42m"
BG_RED = "\033[41m"
BG_YELLOW = "\033[43m"
BG_CYAN = "\033[46m"

# ============================================================
# Custom Logger
# ============================================================
class ColorFormatter(logging.Formatter):
    def format(self, record):
        if record.name in ("uvicorn.access", "httpx"):
            return ""
        return record.getMessage()


logger = logging.getLogger("claude_proxy")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(ColorFormatter())
logger.addHandler(handler)

logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)

LOCAL_PORT = int(os.getenv("LOCAL_PORT", "9999"))
ANTHROPIC_BASE_URL = "https://api.anthropic.com"

# ============================================================
# CONSISTENT SESSION SECRET
# Per-proxy-instance secret for deterministic ID generation.
# All devices using same .env will produce same derived IDs.
# Saved to .env automatically when identity is first captured
# via capture_identity_from_request().
# ============================================================
SESSION_SECRET = os.getenv("SESSION_SECRET", "")
if not SESSION_SECRET:
    SESSION_SECRET = secrets.token_hex(32)

# ============================================================
# TELEMETRY BLOCKING
# Block endpoints that send device telemetry/analytics data.
# Returns fake success responses instead of forwarding.
# ============================================================
BLOCKED_PATH_PATTERNS = [
    r"^v1/telemetry",
    r"^v1/analytics",
    r"^v1/log",
    r"^v1/events",
    r"^v1/diagnostics",
    r"^v1/metrics",
    r"^v1/track",
    r"^v1/report",
    r"^telemetry",
    r"^analytics",
    r"^log_event",
    r"^sentry",
    r"^bugsnag",
]

BLOCKED_PATH_REGEX = [re.compile(p, re.IGNORECASE) for p in BLOCKED_PATH_PATTERNS]

# ============================================================
# BODY SANITIZATION
# Fields in JSON request bodies that could identify individual
# devices. These are replaced with consistent fake values.
# ============================================================
SANITIZE_BODY_FIELDS = {
    "machine_id", "machineId", "machine-id",
    "device_id", "deviceId", "device-id",
    "hostname", "host_name",
    "computer_name", "computerName",
    "username", "user_name", "userName",
    "home_dir", "homeDir", "home_directory",
    "os_version", "osVersion",
    "os_release", "osRelease",
    "platform_version", "platformVersion",
    "mac_address", "macAddress",
    "hardware_id", "hardwareId",
    "installation_id", "installationId",
    "instance_id", "instanceId",
    "client_id", "clientId",
    "workspace_id", "workspaceId",
    "vscode_machine_id", "vscodeMachineId",
    "vscode_session_id", "vscodeSessionId",
}

# Nested objects/paths that could contain device info
SANITIZE_BODY_OBJECTS = {
    "system_info", "systemInfo",
    "device_info", "deviceInfo",
    "machine_info", "machineInfo",
    "environment_info", "environmentInfo",
    "telemetry", "diagnostics",
}

# Pre-computed normalized sets for fast lookup during body sanitization
_SANITIZE_FIELDS_NORMALIZED = {s.lower().replace("-", "_") for s in SANITIZE_BODY_FIELDS}
_SANITIZE_OBJECTS_NORMALIZED = {s.lower().replace("-", "_") for s in SANITIZE_BODY_OBJECTS}

# ============================================================
# CAPTURED IDENTITY - Bắt từ request thật
# Expanded header list for maximum fingerprint coverage
# ============================================================
CAPTURE_HEADERS = [
    # Core identity
    "user-agent",
    "x-claude-code-session-id",
    "x-app",
    # Anthropic-specific
    "anthropic-beta",
    "anthropic-version",
    "anthropic-dangerous-direct-browser-access",
    # Stainless SDK fingerprint
    "x-stainless-os",
    "x-stainless-arch",
    "x-stainless-runtime",
    "x-stainless-runtime-version",
    "x-stainless-lang",
    "x-stainless-package-version",
    "x-stainless-retry-count",
    "x-stainless-read-timeout",
    # HTTP metadata
    "accept-encoding",
    "accept-language",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-dest",
    # Additional tracking vectors
    "origin",
    "referer",
    "x-client-version",
    "x-client-name",
]

# Headers that MUST be stripped from outgoing requests (IP/tracking leaks)
STRIP_REQUEST_HEADERS = {
    "x-forwarded-for",
    "x-real-ip",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-forwarded-port",
    "forwarded",
    "via",
    "x-client-ip",
    "cf-connecting-ip",
    "true-client-ip",
    "x-cluster-client-ip",
    "x-originating-ip",
    "x-remote-ip",
    "x-remote-addr",
    "proxy-connection",
}

# Headers to strip from upstream responses (tracking prevention)
STRIP_RESPONSE_HEADERS = {
    "content-length", "transfer-encoding", "content-encoding",
    "connection", "keep-alive",
    # Tracking/fingerprint headers from server
    "server-timing",
    "x-trace-id",
    "x-span-id",
    "x-request-id",
    "x-correlation-id",
    "x-amzn-trace-id",
    "x-amzn-requestid",
    "x-ray-trace-id",
    "nel",
    "report-to",
    "reporting-endpoints",
}

# Headers đã biết, không cần cảnh báo khi gặp
KNOWN_HEADERS = set(h.lower() for h in CAPTURE_HEADERS) | STRIP_REQUEST_HEADERS | {
    # Excluded từ forward
    "host", "content-length", "transfer-encoding",
    # Sensitive / pass-through
    "authorization", "x-api-key", "cookie",
    # Common HTTP
    "content-type", "accept", "connection", "cache-control",
    "x-request-id", "x-forwarded-for", "x-real-ip",
    "traceparent", "tracestate",
    "pragma", "upgrade-insecure-requests",
    "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
    "dnt", "tk",
}

# ============================================================
# REQUEST TIMING JITTER
# Add random delay to mask multi-device timing patterns.
# Prevents Anthropic from detecting simultaneous requests
# from "the same device" that arrive at different times.
# ============================================================
TIMING_JITTER_ENABLED = os.getenv("TIMING_JITTER", "true").lower() == "true"
TIMING_JITTER_MIN_MS = int(os.getenv("TIMING_JITTER_MIN_MS", "10"))
TIMING_JITTER_MAX_MS = int(os.getenv("TIMING_JITTER_MAX_MS", "150"))

# ============================================================
# TOKEN SAVER MODE
# Reduce input token cost on /v1/messages without changing semantics.
#   1. CACHE_EXTEND_TTL: bump prompt-cache TTL from 5m → 1h on the
#      stable prefix (system block + tool definitions). Requires the
#      `extended-cache-ttl-2025-04-11` Anthropic beta header, which
#      the proxy appends automatically when this is on.
#   2. TOOL_RESULT_TRUNCATE: head+tail truncate large tool_result
#      blocks in OLDER turns of messages[]. Recent turns are kept
#      intact so the agent's active context is not damaged.
# ============================================================
TOKEN_SAVER_ENABLED = os.getenv("TOKEN_SAVER", "false").lower() == "true"
CACHE_EXTEND_TTL = os.getenv("CACHE_EXTEND_TTL", "true").lower() == "true"
TOOL_RESULT_TRUNCATE = os.getenv("TOOL_RESULT_TRUNCATE", "false").lower() == "true"
TOOL_RESULT_MAX_BYTES = int(os.getenv("TOOL_RESULT_MAX_BYTES", "8000"))
TOOL_RESULT_HEAD_BYTES = int(os.getenv("TOOL_RESULT_HEAD_BYTES", "4000"))
TOOL_RESULT_TAIL_BYTES = int(os.getenv("TOOL_RESULT_TAIL_BYTES", "2000"))
TOOL_RESULT_KEEP_RECENT = int(os.getenv("TOOL_RESULT_KEEP_RECENT", "2"))

CACHE_TTL_BETA = "extended-cache-ttl-2025-04-11"
MAX_CACHE_BREAKPOINTS = 4
CHARS_PER_TOKEN = 4

# Runtime flag — set to True if upstream rejects the cache TTL beta header,
# so we stop attaching it for the rest of the process lifetime.
_cache_ttl_runtime_disabled = False

# ============================================================
# QUOTA / COST TRACKING
# Parse `anthropic-ratelimit-*` response headers and `usage` blocks from
# /v1/messages responses (both streaming SSE and non-streaming JSON) to
# surface live remaining quota and accumulated cost across all devices
# sharing this proxy. Useful for multi-device share to avoid surprise
# rate-limit hits.
# ============================================================
QUOTA_TRACKING_ENABLED = os.getenv("QUOTA_TRACKING", "true").lower() == "true"

# Per-million-token USD prices. Defaults are public Anthropic list prices
# at the time of writing — override via PRICING_<KEY>_<TIER>=<usd> env if
# Anthropic changes them or you want plan-specific rates.
#
# Tiers: input, output, cache_write_5m, cache_write_1h, cache_read.
# Model key is matched by substring against the response `model` field.
PRICING_DEFAULTS: dict[str, dict[str, float]] = {
    "opus-4":    {"input": 15.00, "output": 75.00, "cache_write_5m": 18.75, "cache_write_1h": 30.00, "cache_read": 1.50},
    "sonnet-4":  {"input":  3.00, "output": 15.00, "cache_write_5m":  3.75, "cache_write_1h":  6.00, "cache_read": 0.30},
    "haiku-4":   {"input":  1.00, "output":  5.00, "cache_write_5m":  1.25, "cache_write_1h":  2.00, "cache_read": 0.10},
    "opus-3":    {"input": 15.00, "output": 75.00, "cache_write_5m": 18.75, "cache_write_1h": 30.00, "cache_read": 1.50},
    "sonnet-3.7":{"input":  3.00, "output": 15.00, "cache_write_5m":  3.75, "cache_write_1h":  6.00, "cache_read": 0.30},
    "sonnet-3.5":{"input":  3.00, "output": 15.00, "cache_write_5m":  3.75, "cache_write_1h":  6.00, "cache_read": 0.30},
    "haiku-3.5": {"input":  0.80, "output":  4.00, "cache_write_5m":  1.00, "cache_write_1h":  1.60, "cache_read": 0.08},
    "haiku-3":   {"input":  0.25, "output":  1.25, "cache_write_5m":  0.30, "cache_write_1h":  0.50, "cache_read": 0.03},
}


def _load_pricing() -> dict[str, dict[str, float]]:
    """Apply env overrides on top of PRICING_DEFAULTS."""
    pricing = {k: dict(v) for k, v in PRICING_DEFAULTS.items()}
    for model_key in pricing:
        env_prefix = "PRICING_" + model_key.upper().replace("-", "_").replace(".", "_")
        for tier in pricing[model_key]:
            override = os.getenv(f"{env_prefix}_{tier.upper()}")
            if override:
                try:
                    pricing[model_key][tier] = float(override)
                except ValueError:
                    pass
    return pricing


PRICING = _load_pricing()

# Cap on how many bytes the usage extractor will buffer per response, to
# avoid unbounded memory growth on a malformed upstream stream.
USAGE_TAP_MAX_BUFFER = 5 * 1024 * 1024  # 5 MB

quota_stats = {
    "rate_limits": {},  # latest anthropic-ratelimit-* headers seen
    "rate_limits_updated_at": None,
    "usage_total": {
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_creation_input_tokens": 0,
        "cache_creation_5m_input_tokens": 0,
        "cache_creation_1h_input_tokens": 0,
        "cache_read_input_tokens": 0,
    },
    "cost_usd_total": 0.0,
    "by_model": {},  # model_key -> {usage..., cost_usd, requests}
    "by_session": {},  # session_id -> {requests, tokens, cost_usd, first_seen, last_seen}
    "by_day": {},  # YYYY-MM-DD -> {requests, tokens, cost_usd}
    "messages_requests": 0,
    "last_request_at": None,
}

# Caps to prevent unbounded growth of per-session / per-day buckets.
# When a cap is exceeded, oldest entries (by last_seen / date) are evicted.
QUOTA_MAX_SESSIONS = int(os.getenv("QUOTA_MAX_SESSIONS", "100"))
QUOTA_MAX_DAYS = int(os.getenv("QUOTA_MAX_DAYS", "30"))

# ============================================================
# QUOTA PERSISTENCE
# Save accumulated stats to .quota.json (next to .env) so totals survive
# proxy restarts. Writes are debounced — at most once per
# QUOTA_PERSIST_INTERVAL seconds during normal operation, plus a forced
# flush on shutdown via the lifespan hook.
# rate_limits is intentionally NOT persisted (the values are already
# stale by the next process start).
# ============================================================
QUOTA_PERSIST_PATH = os.getenv(
    "QUOTA_PERSIST_PATH",
    os.path.join(os.path.dirname(ENV_PATH), ".quota.json"),
)
QUOTA_PERSIST_INTERVAL_SECONDS = int(os.getenv("QUOTA_PERSIST_INTERVAL", "30"))
QUOTA_SCHEMA_VERSION = 2  # v1 = totals + by_model. v2 adds by_session + by_day.
QUOTA_SCHEMA_MIN_LOAD = 1  # accept v1 files for migration
_last_quota_save_at = 0.0


def env_key(header: str) -> str:
    return "CAPTURED_" + header.upper().replace("-", "_")


captured_identity: dict[str, str] = {}
for h in CAPTURE_HEADERS:
    val = os.getenv(env_key(h), "")
    if val:
        captured_identity[h] = val

identity_captured = bool(captured_identity)
warned_unknown_headers: set[str] = set()
blocked_requests_count = 0
sanitized_bodies_count = 0

token_saver_stats = {
    "requests_optimized": 0,
    "cache_breakpoints_added": 0,
    "cache_breakpoints_skipped_full": 0,
    "tool_results_truncated": 0,
    "bytes_saved": 0,
    "tokens_saved_est": 0,
    "beta_runtime_disabled": False,
}

http_client: httpx.AsyncClient | None = None
request_count = 0


def log(msg: str):
    logger.info(msg)


def save_to_env(key: str, value: str):
    """Lưu hoặc cập nhật 1 key trong .env file."""
    if not os.path.exists(ENV_PATH):
        with open(ENV_PATH, "w") as f:
            f.write(f"{key}={value}\n")
        return

    with open(ENV_PATH, "r") as f:
        content = f.read()

    if f"{key}=" in content:
        content = re.sub(rf"{re.escape(key)}=.*", f"{key}={value}", content)
    else:
        content = content.rstrip("\n") + f"\n{key}={value}\n"

    with open(ENV_PATH, "w") as f:
        f.write(content)


def generate_consistent_id(seed: str) -> str:
    """Generate a consistent ID using HMAC so all devices produce the same value."""
    return hmac.new(
        SESSION_SECRET.encode(),
        seed.encode(),
        hashlib.sha256,
    ).hexdigest()[:32]


def is_blocked_path(path: str) -> bool:
    """Check if path matches any blocked telemetry pattern."""
    for pattern in BLOCKED_PATH_REGEX:
        if pattern.search(path):
            return True
    return False


def sanitize_body(body: bytes, content_type: str | None) -> bytes:
    """Strip device-identifying fields from JSON request bodies."""
    global sanitized_bodies_count

    if not body:
        return body

    if not content_type or "json" not in content_type.lower():
        return body

    try:
        data = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return body

    if not isinstance(data, dict):
        return body

    changed = _sanitize_dict(data)

    if changed:
        sanitized_bodies_count += 1
        return json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode()

    return body


def _sanitize_dict(data: dict) -> bool:
    """Recursively sanitize a dict. Returns True if any field was modified."""
    changed = False

    for key in list(data.keys()):
        key_lower = key.lower().replace("-", "_")

        # Remove entire objects that contain device info
        if key in SANITIZE_BODY_OBJECTS or key_lower in _SANITIZE_OBJECTS_NORMALIZED:
            data[key] = {}
            changed = True
            continue

        # Replace identifying string fields with consistent fakes
        if key in SANITIZE_BODY_FIELDS or key_lower in _SANITIZE_FIELDS_NORMALIZED:
            if isinstance(data[key], str) and data[key]:
                data[key] = generate_consistent_id(key)
                changed = True
            continue

        # Recurse into nested dicts
        if isinstance(data[key], dict):
            if _sanitize_dict(data[key]):
                changed = True
        elif isinstance(data[key], list):
            for item in data[key]:
                if isinstance(item, dict):
                    if _sanitize_dict(item):
                        changed = True

    return changed


def optimize_tokens(body: bytes, content_type: str | None, path: str) -> bytes:
    """Apply token-saving transforms to /v1/messages JSON bodies."""
    if not TOKEN_SAVER_ENABLED or not body:
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

    if CACHE_EXTEND_TTL and not _cache_ttl_runtime_disabled:
        breakpoints, skipped_full = _apply_cache_breakpoints(data)
    if TOOL_RESULT_TRUNCATE:
        truncated = _truncate_tool_results(data)

    if breakpoints == 0 and truncated == 0:
        if skipped_full:
            token_saver_stats["cache_breakpoints_skipped_full"] += skipped_full
        return body

    new_body = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode()
    saved_bytes = max(0, original_size - len(new_body))

    token_saver_stats["requests_optimized"] += 1
    token_saver_stats["cache_breakpoints_added"] += breakpoints
    token_saver_stats["cache_breakpoints_skipped_full"] += skipped_full
    token_saver_stats["tool_results_truncated"] += truncated
    token_saver_stats["bytes_saved"] += saved_bytes
    token_saver_stats["tokens_saved_est"] += saved_bytes // CHARS_PER_TOKEN

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
    budget = MAX_CACHE_BREAKPOINTS - existing
    modified = 0
    skipped = 0

    # Step 1: upgrade EVERY existing cache_control in tools + system to 1h.
    # This is the critical step that prevents "1h after 5m" violations.
    tools = data.get("tools")
    if isinstance(tools, list):
        for tool in tools:
            if isinstance(tool, dict) and isinstance(tool.get("cache_control"), dict):
                if tool["cache_control"].get("ttl") != "1h":
                    tool["cache_control"]["ttl"] = "1h"
                    if tool["cache_control"].get("type") != "ephemeral":
                        tool["cache_control"]["type"] = "ephemeral"
                    modified += 1

    sys_field = data.get("system")
    if isinstance(sys_field, list):
        for block in sys_field:
            if isinstance(block, dict) and isinstance(block.get("cache_control"), dict):
                if block["cache_control"].get("ttl") != "1h":
                    block["cache_control"]["ttl"] = "1h"
                    if block["cache_control"].get("type") != "ephemeral":
                        block["cache_control"]["type"] = "ephemeral"
                    modified += 1

    # Step 2: add a new breakpoint at the stable suffix if there isn't one
    # already AND we have budget. Skip silently when full.
    cc_new = {"type": "ephemeral", "ttl": "1h"}

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
    head = text[:TOOL_RESULT_HEAD_BYTES]
    tail = text[-TOOL_RESULT_TAIL_BYTES:] if TOOL_RESULT_TAIL_BYTES > 0 else ""
    omitted = len(text) - len(head) - len(tail)
    marker = f"\n\n[...{omitted} chars truncated by claude-cloak token-saver...]\n\n"
    return head + marker + tail


def _truncate_tool_results(data: dict) -> int:
    """Truncate oversized tool_result blocks in older turns of messages[]."""
    messages = data.get("messages")
    if not isinstance(messages, list):
        return 0

    cutoff = max(0, len(messages) - TOOL_RESULT_KEEP_RECENT)
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
                if len(tc) > TOOL_RESULT_MAX_BYTES:
                    block["content"] = _head_tail_truncate(tc)
                    truncated += 1
            elif isinstance(tc, list):
                for item in tc:
                    if not isinstance(item, dict) or item.get("type") != "text":
                        continue
                    text = item.get("text", "")
                    if isinstance(text, str) and len(text) > TOOL_RESULT_MAX_BYTES:
                        item["text"] = _head_tail_truncate(text)
                        truncated += 1

    return truncated


def inject_cache_ttl_beta(headers: dict[str, str]) -> None:
    """Append the extended-cache-ttl beta to anthropic-beta header (if not present)."""
    if not (TOKEN_SAVER_ENABLED and CACHE_EXTEND_TTL):
        return
    if _cache_ttl_runtime_disabled:
        return
    for k in list(headers.keys()):
        if k.lower() == "anthropic-beta":
            existing = headers[k]
            betas = {b.strip() for b in existing.split(",") if b.strip()}
            if CACHE_TTL_BETA not in betas:
                headers[k] = existing + "," + CACHE_TTL_BETA if existing else CACHE_TTL_BETA
            return
    headers["anthropic-beta"] = CACHE_TTL_BETA


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
    if "cache_control" in text and ("ttl" in text or "1h" in text or "5m" in text):
        return True
    return False


def disable_cache_ttl_runtime(reason: str):
    """Latch off the extended-cache-ttl beta for the rest of the process."""
    global _cache_ttl_runtime_disabled
    if _cache_ttl_runtime_disabled:
        return
    _cache_ttl_runtime_disabled = True
    token_saver_stats["beta_runtime_disabled"] = True
    log("")
    log(f"  {BG_YELLOW}{BOLD} TOKEN SAVER FALLBACK {RESET} {YELLOW}cache-ttl 1h disabled: {reason}{RESET}")
    log(f"  {YELLOW}Will use Anthropic default 5m cache for the rest of this session.{RESET}")
    log("")


def _load_quota_stats() -> bool:
    """Load persisted quota counters from disk into quota_stats.

    Returns True if a file was loaded, False otherwise. Bad files are
    skipped silently — corrupt persistence shouldn't break the proxy.
    """
    if not QUOTA_TRACKING_ENABLED:
        return False
    if not os.path.exists(QUOTA_PERSIST_PATH):
        return False
    try:
        with open(QUOTA_PERSIST_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return False
    if not isinstance(data, dict):
        return False
    version = data.get("version")
    if not isinstance(version, int) or version < QUOTA_SCHEMA_MIN_LOAD or version > QUOTA_SCHEMA_VERSION:
        return False

    ut = data.get("usage_total")
    if isinstance(ut, dict):
        for k in quota_stats["usage_total"]:
            v = ut.get(k, 0)
            if isinstance(v, int):
                quota_stats["usage_total"][k] = v

    if isinstance(data.get("cost_usd_total"), (int, float)):
        quota_stats["cost_usd_total"] = float(data["cost_usd_total"])
    if isinstance(data.get("messages_requests"), int):
        quota_stats["messages_requests"] = data["messages_requests"]
    if isinstance(data.get("last_request_at"), str):
        quota_stats["last_request_at"] = data["last_request_at"]

    bm = data.get("by_model")
    if isinstance(bm, dict):
        for model_key, bucket in bm.items():
            if isinstance(bucket, dict) and "model" in bucket:
                quota_stats["by_model"][model_key] = bucket

    # v2 fields — absent in v1 files, default to empty dicts.
    bs = data.get("by_session")
    if isinstance(bs, dict):
        for sid, bucket in bs.items():
            if isinstance(bucket, dict) and "session_id" in bucket:
                quota_stats["by_session"][sid] = bucket

    bd = data.get("by_day")
    if isinstance(bd, dict):
        for day, bucket in bd.items():
            if isinstance(bucket, dict) and "date" in bucket:
                quota_stats["by_day"][day] = bucket

    return True


def _save_quota_stats(force: bool = False) -> None:
    """Atomically persist quota counters to disk.

    Debounced: skipped if last write was less than
    QUOTA_PERSIST_INTERVAL_SECONDS ago, unless force=True.
    """
    global _last_quota_save_at
    if not QUOTA_TRACKING_ENABLED:
        return
    now = time.monotonic()
    if not force and now - _last_quota_save_at < QUOTA_PERSIST_INTERVAL_SECONDS:
        return

    payload = {
        "version": QUOTA_SCHEMA_VERSION,
        "saved_at": datetime.now().isoformat(timespec="seconds"),
        "messages_requests": quota_stats["messages_requests"],
        "last_request_at": quota_stats["last_request_at"],
        "usage_total": quota_stats["usage_total"],
        "cost_usd_total": quota_stats["cost_usd_total"],
        "by_model": quota_stats["by_model"],
        "by_session": quota_stats["by_session"],
        "by_day": quota_stats["by_day"],
    }
    tmp_path = QUOTA_PERSIST_PATH + ".tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        os.replace(tmp_path, QUOTA_PERSIST_PATH)
        _last_quota_save_at = now
    except OSError:
        # Disk full / permission issue — skip silently, try again next time.
        pass


def _normalize_model_key(model: str | None) -> str:
    """Map a Claude model id to a PRICING key.

    Anthropic's id ordering varies between generations:
      - 4.x: family-first, e.g. `claude-sonnet-4-5-20250929`
      - 3.x: version-first, e.g. `claude-3-5-sonnet-20241022`

    We match both `<family>-<version>` and `<version>-<family>` forms,
    using a hyphen-normalized version (so `3.5` lines up with `3-5`).
    Longer keys are checked first so `sonnet-3.5` wins over `sonnet-3`.
    """
    if not model:
        return "unknown"
    m = model.lower().replace(".", "-")
    candidates = sorted(
        PRICING.keys(),
        key=lambda k: len(k.replace(".", "-")),
        reverse=True,
    )
    for key in candidates:
        norm_key = key.replace(".", "-")
        family, _, version = norm_key.partition("-")
        if not version:
            if family in m:
                return key
            continue
        if f"{family}-{version}" in m or f"{version}-{family}" in m:
            return key
    return "unknown"


def _record_rate_limits(headers) -> None:
    """Capture anthropic-ratelimit-* and retry-after headers from a response."""
    if not QUOTA_TRACKING_ENABLED:
        return
    latest = {}
    for k, v in headers.items():
        kl = k.lower()
        if kl.startswith("anthropic-ratelimit-"):
            latest[kl[len("anthropic-ratelimit-"):]] = v
        elif kl == "retry-after":
            latest["retry-after"] = v
    if latest:
        quota_stats["rate_limits"] = latest
        quota_stats["rate_limits_updated_at"] = datetime.now().isoformat(timespec="seconds")


def _compute_cost(model_key: str, usage: dict) -> float:
    """Compute USD cost for a single /v1/messages response usage block."""
    p = PRICING.get(model_key)
    if not p:
        return 0.0

    input_t = usage.get("input_tokens", 0) or 0
    output_t = usage.get("output_tokens", 0) or 0
    cache_read = usage.get("cache_read_input_tokens", 0) or 0
    cache_write_total = usage.get("cache_creation_input_tokens", 0) or 0

    cache_write_5m = 0
    cache_write_1h = 0
    cc = usage.get("cache_creation")
    if isinstance(cc, dict):
        cache_write_5m = cc.get("ephemeral_5m_input_tokens", 0) or 0
        cache_write_1h = cc.get("ephemeral_1h_input_tokens", 0) or 0
    if cache_write_5m == 0 and cache_write_1h == 0 and cache_write_total:
        # Older API shape: no breakdown — assume default 5m TTL.
        cache_write_5m = cache_write_total

    cost = (
        input_t * p["input"]
        + output_t * p["output"]
        + cache_read * p["cache_read"]
        + cache_write_5m * p["cache_write_5m"]
        + cache_write_1h * p["cache_write_1h"]
    ) / 1_000_000.0
    return cost


def _record_usage(model: str | None, usage: dict, session_id: str | None = None) -> None:
    """Accumulate a single response's usage into quota_stats and log it.

    `session_id` is the original `x-claude-code-session-id` from the incoming
    request (BEFORE the proxy rewrites it to the locked identity), so each
    device's session shows up separately.
    """
    if not QUOTA_TRACKING_ENABLED or not usage:
        return

    model_key = _normalize_model_key(model)
    cost = _compute_cost(model_key, usage)

    cc = usage.get("cache_creation") if isinstance(usage.get("cache_creation"), dict) else {}
    cw5 = cc.get("ephemeral_5m_input_tokens", 0) or 0
    cw1 = cc.get("ephemeral_1h_input_tokens", 0) or 0

    in_t = usage.get("input_tokens", 0) or 0
    out_t = usage.get("output_tokens", 0) or 0
    cr_t = usage.get("cache_read_input_tokens", 0) or 0
    cw_t = usage.get("cache_creation_input_tokens", 0) or 0

    totals = quota_stats["usage_total"]
    totals["input_tokens"] += in_t
    totals["output_tokens"] += out_t
    totals["cache_creation_input_tokens"] += cw_t
    totals["cache_creation_5m_input_tokens"] += cw5
    totals["cache_creation_1h_input_tokens"] += cw1
    totals["cache_read_input_tokens"] += cr_t

    quota_stats["cost_usd_total"] += cost
    quota_stats["messages_requests"] += 1
    now_iso = datetime.now().isoformat(timespec="seconds")
    quota_stats["last_request_at"] = now_iso

    bucket = quota_stats["by_model"].setdefault(model_key, {
        "model": model_key,
        "requests": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 0,
        "cost_usd": 0.0,
    })
    bucket["requests"] += 1
    bucket["input_tokens"] += in_t
    bucket["output_tokens"] += out_t
    bucket["cache_creation_input_tokens"] += cw_t
    bucket["cache_read_input_tokens"] += cr_t
    bucket["cost_usd"] += cost

    if session_id:
        sb = quota_stats["by_session"].setdefault(session_id, {
            "session_id": session_id,
            "requests": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "cache_creation_input_tokens": 0,
            "cache_read_input_tokens": 0,
            "cost_usd": 0.0,
            "models": {},
            "first_seen": now_iso,
            "last_seen": now_iso,
        })
        sb["requests"] += 1
        sb["input_tokens"] += in_t
        sb["output_tokens"] += out_t
        sb["cache_creation_input_tokens"] += cw_t
        sb["cache_read_input_tokens"] += cr_t
        sb["cost_usd"] += cost
        sb["last_seen"] = now_iso
        sb["models"][model_key] = sb["models"].get(model_key, 0) + 1
        _evict_oldest("by_session", "last_seen", QUOTA_MAX_SESSIONS)

    today = datetime.now().strftime("%Y-%m-%d")
    db = quota_stats["by_day"].setdefault(today, {
        "date": today,
        "requests": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 0,
        "cost_usd": 0.0,
    })
    db["requests"] += 1
    db["input_tokens"] += in_t
    db["output_tokens"] += out_t
    db["cache_creation_input_tokens"] += cw_t
    db["cache_read_input_tokens"] += cr_t
    db["cost_usd"] += cost
    _evict_oldest("by_day", "date", QUOTA_MAX_DAYS)

    log(
        f"           {DIM}usage: {RESET}{CYAN}{model_key}{RESET} "
        f"{DIM}in={in_t} out={out_t} cache_r={cr_t} cache_w={cw_t} "
        f"cost=${cost:.4f}{RESET}"
    )

    _save_quota_stats()


def _evict_oldest(field: str, sort_key: str, max_entries: int) -> None:
    """Drop oldest entries from quota_stats[field] when over max_entries.

    `sort_key` is the bucket field used to determine age (date string or
    ISO timestamp — both sort lexicographically).
    """
    bucket = quota_stats[field]
    if len(bucket) <= max_entries:
        return
    items = sorted(bucket.items(), key=lambda kv: kv[1].get(sort_key, ""))
    drop = len(bucket) - max_entries
    for key, _ in items[:drop]:
        del bucket[key]


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

    def __init__(self, content_type: str | None, path: str, session_id: str | None = None):
        self.path = path
        self.session_id = session_id
        self.is_messages = "v1/messages" in path
        ct = (content_type or "").lower()
        self.is_sse = "event-stream" in ct
        self.is_json = "json" in ct and not self.is_sse
        self.buffer = bytearray()
        self.usage: dict = {}
        self.model: str | None = None
        self.cache_creation: dict | None = None
        self._overflow = False

    def feed(self, chunk: bytes) -> None:
        if not self.is_messages or not chunk or self._overflow:
            return
        if len(self.buffer) + len(chunk) > USAGE_TAP_MAX_BUFFER:
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
        if self.cache_creation is not None:
            self.usage["cache_creation"] = self.cache_creation
        # Free the buffer; we're done with it.
        self.buffer.clear()
        return self.model, dict(self.usage)


def capture_identity_from_request(request: Request):
    global identity_captured, captured_identity

    if identity_captured:
        return

    req_headers = {k.lower(): v for k, v in request.headers.items()}

    for h in CAPTURE_HEADERS:
        val = req_headers.get(h, "")
        if val:
            captured_identity[h] = val
            save_to_env(env_key(h), val)

    if captured_identity:
        identity_captured = True

        # Save session secret for consistent ID generation across devices
        save_to_env("SESSION_SECRET", SESSION_SECRET)

        log("")
        log(f"  {BG_GREEN}{BOLD} IDENTITY CAPTURED {RESET}")
        log(f"  {GREEN}Da bat {len(captured_identity)} headers tu Claude Code:{RESET}")
        for h, v in captured_identity.items():
            display = mask_value(v, 40) if len(v) > 50 else v
            log(f"    {MAGENTA}{h}{RESET}: {WHITE}{display}{RESET}")
        log(f"  {YELLOW}Da luu vao .env - Copy sang cac may khac!{RESET}")
        log("")


def warn_unknown_headers(request: Request):
    """Cảnh báo khi gặp header lạ chưa có trong danh sách đã biết."""
    global warned_unknown_headers

    req_headers = {k.lower() for k in request.headers.keys()}
    new_unknown = req_headers - KNOWN_HEADERS - warned_unknown_headers

    for h in sorted(new_unknown):
        warned_unknown_headers.add(h)
        log(f"  {BG_YELLOW}{BOLD} HEADER LA {RESET} {YELLOW}{BOLD}{h}{RESET}{YELLOW}: {request.headers.get(h, '')}{RESET}")
        log(f"  {YELLOW}Header nay chua co trong CAPTURE_HEADERS, kiem tra xem co can lock khong!{RESET}")
        log("")


def print_banner():
    banner = f"""
{MAGENTA}{BOLD}
     ██████╗██╗      █████╗ ██╗   ██╗██████╗ ███████╗
    ██╔════╝██║     ██╔══██╗██║   ██║██╔══██╗██╔════╝
    ██║     ██║     ███████║██║   ██║██║  ██║█████╗
    ██║     ██║     ██╔══██║██║   ██║██║  ██║██╔══╝
    ╚██████╗███████╗██║  ██║╚██████╔╝██████╔╝███████╗
     ╚═════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝
{RESET}{CYAN}{BOLD}               ██████╗██╗      ██████╗  █████╗ ██╗  ██╗
              ██╔════╝██║     ██╔═══██╗██╔══██╗██║ ██╔╝
              ██║     ██║     ██║   ██║███████║█████╔╝
              ██║     ██║     ██║   ██║██╔══██║██╔═██╗
              ╚██████╗███████╗╚██████╔╝██║  ██║██║  ██╗
               ╚═════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝{RESET}
"""
    print(banner)


def mask_value(val: str, show=12) -> str:
    if len(val) <= show + 4:
        return val
    return f"{val[:show]}...{val[-4:]}"


def print_status():
    identity_status = f"{GREEN}{len(captured_identity)} headers locked{RESET}" if identity_captured else f"{YELLOW}Waiting for first request...{RESET}"

    jitter_status = f"{GREEN}ON ({TIMING_JITTER_MIN_MS}-{TIMING_JITTER_MAX_MS}ms){RESET}" if TIMING_JITTER_ENABLED else f"{YELLOW}OFF{RESET}"
    telemetry_status = f"{GREEN}{len(BLOCKED_PATH_PATTERNS)} patterns blocked{RESET}"

    print(f"  {DIM}{'─' * 60}{RESET}")
    print(f"  {CYAN} Server      {RESET}{WHITE}http://localhost:{LOCAL_PORT}{RESET}")
    print(f"  {CYAN} Target      {RESET}{WHITE}{ANTHROPIC_BASE_URL}{RESET}")
    print(f"  {DIM}{'─' * 60}{RESET}")
    print(f"  {CYAN} Identity    {RESET}{identity_status}")
    print(f"  {CYAN} Telemetry   {RESET}{telemetry_status}")
    print(f"  {CYAN} Timing      {RESET}{jitter_status}")
    print(f"  {CYAN} Body Scrub  {RESET}{GREEN}{len(SANITIZE_BODY_FIELDS)} fields monitored{RESET}")
    print(f"  {CYAN} IP Strip    {RESET}{GREEN}{len(STRIP_REQUEST_HEADERS)} headers stripped{RESET}")
    if TOKEN_SAVER_ENABLED:
        ts_parts = []
        if CACHE_EXTEND_TTL:
            ts_parts.append("cache 1h")
        if TOOL_RESULT_TRUNCATE:
            ts_parts.append(f"tool-trunc>{TOOL_RESULT_MAX_BYTES}b")
        ts_status = f"{GREEN}ON ({', '.join(ts_parts) or 'no-op'}){RESET}"
    else:
        ts_status = f"{YELLOW}OFF{RESET}"
    print(f"  {CYAN} Token Saver {RESET}{ts_status}")
    if QUOTA_TRACKING_ENABLED:
        if quota_stats["messages_requests"]:
            cost = quota_stats["cost_usd_total"]
            reqs = quota_stats["messages_requests"]
            quota_status = (
                f"{GREEN}ON{RESET} "
                f"{DIM}(loaded ${cost:.4f} / {reqs} reqs from .quota.json){RESET}"
            )
        else:
            quota_status = f"{GREEN}ON{RESET}"
    else:
        quota_status = f"{YELLOW}OFF{RESET}"
    print(f"  {CYAN} Quota Track {RESET}{quota_status}")
    if QUOTA_TRACKING_ENABLED:
        print(f"  {CYAN} Dashboard   {RESET}{WHITE}http://localhost:{LOCAL_PORT}/dashboard{RESET}")
    if identity_captured:
        print(f"  {DIM}{'─' * 60}{RESET}")
        for h, v in captured_identity.items():
            display = mask_value(v, 40) if len(v) > 50 else v
            print(f"  {DIM}  {h}: {MAGENTA}{display}{RESET}")
    print(f"  {DIM}{'─' * 60}{RESET}")
    print()


@asynccontextmanager
async def lifespan(app: FastAPI):
    global http_client
    http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(300.0, connect=10.0),
        limits=httpx.Limits(
            max_connections=10,
            max_keepalive_connections=5,
            keepalive_expiry=30.0,
        ),
    )
    _load_quota_stats()
    print_banner()
    print_status()
    try:
        yield
    finally:
        _save_quota_stats(force=True)
        await http_client.aclose()


app = FastAPI(title="Claude Cloak", lifespan=lifespan)


# Headers không forward từ client request
EXCLUDED_REQUEST_HEADERS = {
    "host", "content-length", "transfer-encoding",
}


def build_request_headers(request: Request) -> dict[str, str]:
    headers = {}

    for k, v in request.headers.items():
        kl = k.lower()

        # Skip excluded headers
        if kl in EXCLUDED_REQUEST_HEADERS:
            continue

        # Strip IP-leaking headers
        if kl in STRIP_REQUEST_HEADERS:
            continue

        # Strip cookies to prevent cross-device tracking
        if kl == "cookie":
            continue

        headers[k] = v

    # Override identity headers với giá trị đã lock
    if captured_identity:
        for k in list(headers.keys()):
            kl = k.lower()
            if kl in captured_identity:
                headers[k] = captured_identity[kl]

        # Add any captured headers that aren't in the request
        # (ensures consistent fingerprint even if client omits some)
        existing_lower = {k.lower() for k in headers}
        for h, v in captured_identity.items():
            if h not in existing_lower:
                headers[h] = v

    # Replace x-request-id with a fresh random UUID to avoid
    # leaking per-device identifiers while keeping each request unique
    for k in list(headers.keys()):
        if k.lower() == "x-request-id":
            headers[k] = secrets.token_hex(16)
            break

    return headers


def filter_response_headers(response: httpx.Response) -> dict[str, str]:
    return {
        k: v for k, v in response.headers.items()
        if k.lower() not in STRIP_RESPONSE_HEADERS
    }


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "identity_captured": identity_captured,
        "headers_locked": len(captured_identity),
        "telemetry_blocked": blocked_requests_count,
        "bodies_sanitized": sanitized_bodies_count,
        "ip_headers_stripped": len(STRIP_REQUEST_HEADERS),
        "unknown_headers_seen": sorted(warned_unknown_headers),
        "token_saver": {
            "enabled": TOKEN_SAVER_ENABLED,
            "cache_extend_ttl_configured": CACHE_EXTEND_TTL,
            "cache_extend_ttl_active": (
                CACHE_EXTEND_TTL and not _cache_ttl_runtime_disabled
            ),
            "tool_result_truncate": TOOL_RESULT_TRUNCATE,
            "tool_result_max_bytes": TOOL_RESULT_MAX_BYTES,
            **token_saver_stats,
        },
        "quota": {
            "enabled": QUOTA_TRACKING_ENABLED,
            "messages_requests": quota_stats["messages_requests"],
            "last_request_at": quota_stats["last_request_at"],
            "rate_limits": quota_stats["rate_limits"],
            "rate_limits_updated_at": quota_stats["rate_limits_updated_at"],
            "usage_total": quota_stats["usage_total"],
            "cost_usd_total": round(quota_stats["cost_usd_total"], 6),
            "by_model": [
                {**v, "cost_usd": round(v["cost_usd"], 6)}
                for v in quota_stats["by_model"].values()
            ],
            "by_session_count": len(quota_stats["by_session"]),
            "by_day_count": len(quota_stats["by_day"]),
        },
    }


DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Claude Cloak — Quota & Cost Dashboard</title>
<link rel="preconnect" href="https://cdn.jsdelivr.net" crossorigin>
<style>
  /*  Design tokens  ------------------------------------------------------- */
  :root {
    --bg-0:        #0a0a0d;
    --bg-1:        #111118;
    --bg-2:        #1a1a24;
    --bg-3:        #232330;
    --border:      #2a2a3a;
    --border-soft: #1f1f2c;
    --text:        #ebebf0;
    --text-soft:   #b8b8c4;
    --muted:       #7c7c8c;
    --muted-2:     #555566;
    --accent:      #c084fc;
    --accent-2:    #67e8f9;
    --ok:          #4ade80;
    --warn:        #fbbf24;
    --danger:      #f87171;
    --shadow:      0 1px 3px rgba(0,0,0,.4), 0 1px 0 rgba(255,255,255,.02) inset;
    --radius:      10px;
    --radius-sm:   6px;
    --font-sans:   -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", Roboto, system-ui, sans-serif;
    --font-mono:   ui-monospace, "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
  }

  /*  Reset & base  ------------------------------------------------------- */
  *, *::before, *::after { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; }
  body {
    background: var(--bg-0);
    color: var(--text);
    font: 14px/1.5 var(--font-sans);
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
    min-height: 100vh;
  }
  .num, code { font-family: var(--font-mono); font-variant-numeric: tabular-nums; }
  a { color: var(--accent-2); text-decoration: none; }
  a:hover { text-decoration: underline; }

  /*  Top bar  ------------------------------------------------------------ */
  .topbar {
    position: sticky; top: 0; z-index: 10;
    display: flex; align-items: center; gap: 16px;
    padding: 14px 28px;
    background: rgba(10,10,13,.85);
    backdrop-filter: blur(8px);
    border-bottom: 1px solid var(--border);
  }
  .brand {
    display: flex; align-items: center; gap: 10px;
    font-weight: 600; letter-spacing: 0.01em;
  }
  .brand-mark {
    width: 22px; height: 22px;
    background: linear-gradient(135deg, var(--accent), var(--accent-2));
    border-radius: 5px;
    box-shadow: 0 0 12px rgba(192,132,252,.35);
  }
  .brand-name { color: var(--text); }
  .brand-tag  { color: var(--muted); font-weight: 500; font-size: 12px; margin-left: 4px; }
  .topbar-spacer { flex: 1; }
  .pill {
    display: inline-flex; align-items: center; gap: 6px;
    padding: 5px 11px;
    background: var(--bg-2);
    border: 1px solid var(--border);
    border-radius: 999px;
    font-size: 12px;
    color: var(--text-soft);
  }
  .pill.live   { color: var(--ok); }
  .pill.error  { color: var(--danger); }
  .pill .dot {
    width: 7px; height: 7px; border-radius: 50%;
    background: currentColor;
    box-shadow: 0 0 0 0 currentColor;
    animation: pulse 2s infinite;
  }
  .pill.error .dot { animation: none; }
  @keyframes pulse {
    0%   { box-shadow: 0 0 0 0   rgba(74,222,128,.45); }
    70%  { box-shadow: 0 0 0 6px rgba(74,222,128,0); }
    100% { box-shadow: 0 0 0 0   rgba(74,222,128,0); }
  }

  /*  Layout  ------------------------------------------------------------- */
  main {
    max-width: 1320px; margin: 0 auto;
    padding: 28px;
  }
  section { margin-bottom: 32px; }
  .section-head {
    display: flex; align-items: baseline; gap: 12px;
    margin: 0 4px 14px;
  }
  .section-head h2 {
    margin: 0;
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: var(--muted);
  }
  .section-head .hint {
    font-size: 12px;
    color: var(--muted-2);
  }

  /*  Cards  --------------------------------------------------------------- */
  .grid-cards {
    display: grid;
    grid-template-columns: repeat(12, 1fr);
    gap: 14px;
  }
  .card {
    background: var(--bg-1);
    border: 1px solid var(--border-soft);
    border-radius: var(--radius);
    padding: 18px 20px;
    box-shadow: var(--shadow);
    grid-column: span 3;
    transition: border-color .2s;
  }
  .card:hover { border-color: var(--border); }
  .card .card-label {
    color: var(--muted);
    font-size: 11px;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 10px;
    display: flex; align-items: center; gap: 6px;
  }
  .card .card-value {
    font-family: var(--font-mono);
    font-size: 22px;
    font-weight: 600;
    color: var(--text);
    letter-spacing: -0.01em;
  }
  .card .card-meta {
    margin-top: 8px;
    font-size: 12px;
    color: var(--muted);
  }
  .card.hero {
    grid-column: span 6;
    background:
      radial-gradient(circle at 0% 0%, rgba(192,132,252,.10), transparent 50%),
      radial-gradient(circle at 100% 100%, rgba(103,232,249,.06), transparent 50%),
      var(--bg-1);
    border-color: var(--border);
  }
  .card.hero .card-value {
    font-size: 38px;
    background: linear-gradient(135deg, var(--accent), var(--accent-2));
    -webkit-background-clip: text;
    background-clip: text;
    -webkit-text-fill-color: transparent;
  }
  .card.hero .card-meta { color: var(--text-soft); }

  /*  Panel  --------------------------------------------------------------- */
  .panel {
    background: var(--bg-1);
    border: 1px solid var(--border-soft);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
  }
  .panel-body { padding: 20px 22px; }
  .panel-title {
    display: flex; align-items: baseline; gap: 10px;
    padding: 14px 22px 12px;
    border-bottom: 1px solid var(--border-soft);
  }
  .panel-title h3 {
    margin: 0;
    font-size: 13px;
    font-weight: 600;
    color: var(--text);
    letter-spacing: 0.01em;
  }
  .panel-title .sub { color: var(--muted); font-size: 12px; }

  /*  Bars  ---------------------------------------------------------------- */
  .bar-row {
    display: grid;
    grid-template-columns: 160px 1fr auto;
    align-items: center;
    gap: 16px;
    padding: 9px 0;
  }
  .bar-row + .bar-row { border-top: 1px dashed var(--border-soft); }
  .bar-label { color: var(--text-soft); font-size: 13px; }
  .bar-track {
    position: relative;
    height: 8px; background: var(--bg-3);
    border-radius: 4px; overflow: hidden;
  }
  .bar-fill {
    height: 100%;
    border-radius: 4px;
    transition: width .5s cubic-bezier(.4,.0,.2,1), background-color .2s;
  }
  .bar-row.ok     .bar-fill { background: var(--ok); }
  .bar-row.warn   .bar-fill { background: var(--warn); }
  .bar-row.danger .bar-fill { background: var(--danger); }
  .bar-value {
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--text);
    text-align: right;
    min-width: 220px;
  }
  .bar-value .reset { color: var(--muted); margin-left: 6px; }
  .empty-bars {
    color: var(--muted);
    font-size: 13px;
    padding: 12px 0;
    text-align: center;
  }
  .retry-banner {
    margin-top: 14px;
    padding: 10px 14px;
    background: rgba(248,113,113,.08);
    border: 1px solid rgba(248,113,113,.25);
    border-radius: var(--radius-sm);
    color: var(--danger);
    font-size: 13px;
  }

  /*  Charts grid  --------------------------------------------------------- */
  .charts-grid {
    display: grid;
    grid-template-columns: 2fr 1fr;
    gap: 18px;
  }
  .chart-canvas-wrap { position: relative; height: 280px; padding: 16px 4px 4px; }

  /*  Tables  -------------------------------------------------------------- */
  table { width: 100%; border-collapse: collapse; }
  thead th {
    text-align: left;
    padding: 10px 16px;
    background: var(--bg-2);
    color: var(--muted);
    font-weight: 500;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    border-bottom: 1px solid var(--border-soft);
  }
  tbody td {
    padding: 11px 16px;
    border-bottom: 1px solid var(--border-soft);
    font-size: 13px;
  }
  tbody tr:last-child td { border-bottom: 0; }
  tbody tr:hover td { background: var(--bg-2); }
  td.num, th.num { text-align: right; font-family: var(--font-mono); }
  td.cost { color: var(--accent); font-family: var(--font-mono); font-weight: 500; }
  td.session-id { font-family: var(--font-mono); color: var(--accent-2); }
  td.session-id .session-tail { color: var(--muted); }
  td .badge {
    display: inline-block;
    padding: 1px 7px;
    background: var(--bg-3);
    border-radius: 4px;
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--text-soft);
    margin-right: 4px;
  }
  td .timestamp {
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--text-soft);
  }
  td .timestamp small { color: var(--muted); margin-left: 4px; }

  /*  Empty state  ---------------------------------------------------------- */
  .empty-state {
    padding: 36px;
    text-align: center;
    color: var(--muted);
    font-size: 13px;
  }
  .empty-state strong { color: var(--text-soft); display: block; margin-bottom: 4px; font-weight: 500; }

  /*  Footer  -------------------------------------------------------------- */
  footer {
    max-width: 1320px;
    margin: 0 auto;
    padding: 24px 28px 40px;
    color: var(--muted);
    font-size: 12px;
    border-top: 1px solid var(--border-soft);
    margin-top: 16px;
    display: flex; gap: 16px; flex-wrap: wrap;
  }
  footer .dot-sep { color: var(--muted-2); }

  /*  Responsive  ----------------------------------------------------------- */
  @media (max-width: 960px) {
    .card        { grid-column: span 6; }
    .card.hero   { grid-column: span 12; }
    .charts-grid { grid-template-columns: 1fr; }
    .bar-row     { grid-template-columns: 1fr; gap: 4px; }
    .bar-value   { text-align: left; }
  }
  @media (max-width: 560px) {
    .card        { grid-column: span 12; }
    main         { padding: 18px; }
    .topbar      { padding: 12px 18px; }
  }
</style>
</head>
<body>

<header class="topbar">
  <div class="brand">
    <div class="brand-mark"></div>
    <span class="brand-name">Claude Cloak</span>
    <span class="brand-tag">· Quota & Cost</span>
  </div>
  <div class="topbar-spacer"></div>
  <span class="pill" id="last-refresh" title="Time of last successful /quota fetch">—</span>
  <span class="pill live" id="status-pill"><span class="dot"></span><span id="status-text">connecting…</span></span>
</header>

<main>

  <!-- Totals -->
  <section>
    <div class="section-head">
      <h2>Totals</h2>
      <span class="hint">Lifetime — persisted across restarts</span>
    </div>
    <div class="grid-cards">
      <div class="card hero">
        <div class="card-label">Total Cost (estimated)</div>
        <div class="card-value num" id="cost-total">$0.0000</div>
        <div class="card-meta" id="cost-meta">No requests recorded yet</div>
      </div>
      <div class="card">
        <div class="card-label">Requests</div>
        <div class="card-value num" id="req-total">0</div>
        <div class="card-meta">on /v1/messages</div>
      </div>
      <div class="card">
        <div class="card-label">Distinct sessions</div>
        <div class="card-value num" id="session-count">0</div>
        <div class="card-meta">x-claude-code-session-id</div>
      </div>
      <div class="card">
        <div class="card-label">Input tokens (paid)</div>
        <div class="card-value num" id="in-total">0</div>
      </div>
      <div class="card">
        <div class="card-label">Output tokens</div>
        <div class="card-value num" id="out-total">0</div>
      </div>
      <div class="card">
        <div class="card-label">Cache read</div>
        <div class="card-value num" id="cache-read">0</div>
        <div class="card-meta">10% of input price</div>
      </div>
      <div class="card">
        <div class="card-label">Cache write</div>
        <div class="card-value num" id="cache-write">0</div>
        <div class="card-meta">125% (5m) / 200% (1h)</div>
      </div>
    </div>
  </section>

  <!-- Rate limits -->
  <section>
    <div class="section-head">
      <h2>Rate Limits</h2>
      <span class="hint">Live from Anthropic — last response headers</span>
    </div>
    <div class="panel">
      <div class="panel-body">
        <div id="rate-limits"></div>
      </div>
    </div>
  </section>

  <!-- Daily trend + Cost by model -->
  <section>
    <div class="section-head">
      <h2>Daily Trend</h2>
      <span class="hint">Last 15 days — cost &amp; tokens per day (local time)</span>
    </div>
    <div class="charts-grid">
      <div class="panel">
        <div class="panel-title">
          <h3>Cost & tokens / day</h3>
          <span class="sub" id="daily-range">—</span>
        </div>
        <div class="chart-canvas-wrap"><canvas id="daily-chart"></canvas></div>
      </div>
      <div class="panel">
        <div class="panel-title">
          <h3>Cost by model</h3>
          <span class="sub">lifetime</span>
        </div>
        <div class="chart-canvas-wrap"><canvas id="model-chart"></canvas></div>
      </div>
    </div>
  </section>

  <!-- Daily table -->
  <section>
    <div class="section-head">
      <h2>Daily Breakdown</h2>
      <span class="hint">Most recent first</span>
    </div>
    <div class="panel">
      <table id="daily-table">
        <thead><tr>
          <th>Date</th>
          <th class="num">Requests</th>
          <th class="num">Input</th>
          <th class="num">Output</th>
          <th class="num">Cache R</th>
          <th class="num">Cache W</th>
          <th class="num">Cost</th>
        </tr></thead>
        <tbody></tbody>
      </table>
      <div class="empty-state" id="daily-empty" style="display:none">
        <strong>No daily data yet</strong>
        Send a request to <code>/v1/messages</code> through the proxy to populate.
      </div>
    </div>
  </section>

  <!-- Per-model -->
  <section>
    <div class="section-head">
      <h2>Per-Model Breakdown</h2>
      <span class="hint">Lifetime totals</span>
    </div>
    <div class="panel">
      <table id="model-table">
        <thead><tr>
          <th>Model</th>
          <th class="num">Requests</th>
          <th class="num">Input</th>
          <th class="num">Output</th>
          <th class="num">Cache R</th>
          <th class="num">Cache W</th>
          <th class="num">Cost</th>
        </tr></thead>
        <tbody></tbody>
      </table>
      <div class="empty-state" id="model-empty" style="display:none">
        <strong>No model data yet</strong>
        Per-model breakdown appears after the first response.
      </div>
    </div>
  </section>

  <!-- Per-session -->
  <section>
    <div class="section-head">
      <h2>Per-Session Breakdown</h2>
      <span class="hint">Each device sends its own <code>x-claude-code-session-id</code> — the proxy locks identity outbound but keeps each session distinct here</span>
    </div>
    <div class="panel">
      <table id="session-table">
        <thead><tr>
          <th>Session</th>
          <th>Models</th>
          <th class="num">Requests</th>
          <th class="num">Tokens (in/out)</th>
          <th class="num">Cost</th>
          <th>Last seen</th>
        </tr></thead>
        <tbody></tbody>
      </table>
      <div class="empty-state" id="session-empty" style="display:none">
        <strong>No session data yet</strong>
        Sessions appear once the proxy sees an <code>x-claude-code-session-id</code> header.
      </div>
    </div>
  </section>

</main>

<footer>
  <span>Source: <code>GET /quota</code></span>
  <span class="dot-sep">·</span>
  <span>Persisted to <code>.quota.json</code></span>
  <span class="dot-sep">·</span>
  <span>Auto-refresh every 5 s</span>
  <span class="dot-sep">·</span>
  <span>Costs are <em>estimates</em> — not your actual subscription bill</span>
</footer>

<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<script>
  /*  Formatting helpers  ------------------------------------------------- */
  const fmtCount = new Intl.NumberFormat('en-US');
  function fmtNum(n) {
    n = Number(n) || 0;
    if (n >= 1e9) return (n / 1e9).toFixed(2) + 'B';
    if (n >= 1e6) return (n / 1e6).toFixed(2) + 'M';
    if (n >= 1e4) return (n / 1e3).toFixed(1) + 'K';
    return fmtCount.format(Math.round(n));
  }
  function fmtCost(c) {
    const v = Number(c) || 0;
    if (v === 0) return '$0.00';
    if (v < 0.01) return '$' + v.toFixed(4);
    if (v < 1) return '$' + v.toFixed(3);
    return '$' + v.toFixed(2);
  }
  function fmtCostExact(c) { return '$' + (Number(c) || 0).toFixed(4); }
  function fmtRelativeTime(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    if (isNaN(d)) return iso;
    const diff = (Date.now() - d.getTime()) / 1000;
    if (diff < 5) return 'just now';
    if (diff < 60) return Math.round(diff) + 's ago';
    if (diff < 3600) return Math.round(diff / 60) + 'm ago';
    if (diff < 86400) return Math.round(diff / 3600) + 'h ago';
    return Math.round(diff / 86400) + 'd ago';
  }
  function shortSession(id) {
    if (!id) return '—';
    if (id.length <= 14) return id;
    return id.slice(0, 8) + '…' + id.slice(-4);
  }

  /*  Rate-limit progress bars  ------------------------------------------- */
  function addBar(container, label, remaining, limit, reset) {
    if (remaining == null || limit == null) return false;
    const r = Number(remaining), l = Number(limit);
    if (!Number.isFinite(r) || !Number.isFinite(l) || l <= 0) return false;
    const pct = Math.max(0, Math.min(100, (r / l) * 100));
    const cls = pct < 10 ? 'danger' : pct < 30 ? 'warn' : 'ok';
    const div = document.createElement('div');
    div.className = 'bar-row ' + cls;
    const resetText = reset ? `<span class="reset">resets ${reset}</span>` : '';
    div.innerHTML = `
      <div class="bar-label">${label}</div>
      <div class="bar-track"><div class="bar-fill" style="width:${pct.toFixed(1)}%"></div></div>
      <div class="bar-value">${fmtNum(r)} / ${fmtNum(l)} ${resetText}</div>`;
    container.appendChild(div);
    return true;
  }

  /*  Chart factories  ---------------------------------------------------- */
  let dailyChart = null, modelChart = null;
  const PALETTE = ['#c084fc','#67e8f9','#fbbf24','#4ade80','#f87171','#60a5fa','#f472b6','#a78bfa'];
  const GRID_COLOR = '#22222e';
  const TICK_COLOR = '#7c7c8c';

  const COMMON_OPTS = {
    maintainAspectRatio: false,
    responsive: true,
    interaction: { mode: 'index', intersect: false },
    plugins: {
      legend: { display: true, labels: { color: '#b8b8c4', boxWidth: 10, font: { size: 11 } } },
      tooltip: {
        backgroundColor: '#15151e',
        borderColor: '#2a2a3a', borderWidth: 1,
        titleColor: '#ebebf0', bodyColor: '#b8b8c4',
        padding: 10, cornerRadius: 6,
        titleFont: { size: 12, weight: 600 }, bodyFont: { size: 12 },
      },
    },
  };

  function buildDailyChart(days) {
    days = days.slice().reverse(); // oldest -> newest for x-axis
    const labels = days.map(d => d.date.slice(5)); // MM-DD
    const cost = days.map(d => Number(d.cost_usd) || 0);
    const inTok = days.map(d => Number(d.input_tokens) || 0);
    const outTok = days.map(d => Number(d.output_tokens) || 0);
    const cfg = {
      data: {
        labels,
        datasets: [
          { type: 'line', label: 'Cost (USD)', data: cost,
            yAxisID: 'y',
            borderColor: '#c084fc', backgroundColor: 'rgba(192,132,252,.15)',
            tension: .3, fill: true, pointRadius: 3, pointHoverRadius: 5,
            borderWidth: 2 },
          { type: 'bar', label: 'Input tokens', data: inTok,
            yAxisID: 'y1',
            backgroundColor: 'rgba(103,232,249,.55)', borderRadius: 3, barPercentage: 0.8 },
          { type: 'bar', label: 'Output tokens', data: outTok,
            yAxisID: 'y1',
            backgroundColor: 'rgba(74,222,128,.55)', borderRadius: 3, barPercentage: 0.8 },
        ],
      },
      options: {
        ...COMMON_OPTS,
        scales: {
          x: { ticks: { color: TICK_COLOR, font: { size: 11 } }, grid: { display: false } },
          y: {
            position: 'left', beginAtZero: true,
            ticks: { color: TICK_COLOR, font: { size: 11 }, callback: v => '$' + Number(v).toFixed(2) },
            grid: { color: GRID_COLOR },
            title: { display: true, text: 'Cost (USD)', color: TICK_COLOR, font: { size: 11 } },
          },
          y1: {
            position: 'right', beginAtZero: true,
            ticks: { color: TICK_COLOR, font: { size: 11 }, callback: v => fmtNum(v) },
            grid: { display: false },
            title: { display: true, text: 'Tokens', color: TICK_COLOR, font: { size: 11 } },
          },
        },
        plugins: {
          ...COMMON_OPTS.plugins,
          tooltip: {
            ...COMMON_OPTS.plugins.tooltip,
            callbacks: {
              label: ctx => {
                if (ctx.dataset.label === 'Cost (USD)') return ' Cost: ' + fmtCostExact(ctx.parsed.y);
                return ' ' + ctx.dataset.label + ': ' + fmtCount.format(ctx.parsed.y);
              },
            },
          },
        },
      },
    };
    if (!dailyChart) {
      dailyChart = new Chart(document.getElementById('daily-chart'), cfg);
    } else {
      dailyChart.data = cfg.data; dailyChart.update();
    }
  }

  function buildModelChart(models) {
    const labels = models.map(m => m.model);
    const data = models.map(m => Number(m.cost_usd) || 0);
    const colors = labels.map((_, i) => PALETTE[i % PALETTE.length]);
    const cfg = {
      type: 'doughnut',
      data: {
        labels,
        datasets: [{ data, backgroundColor: colors, borderColor: '#111118', borderWidth: 2, hoverOffset: 4 }],
      },
      options: {
        ...COMMON_OPTS,
        cutout: '62%',
        plugins: {
          legend: { position: 'bottom', labels: { color: '#b8b8c4', boxWidth: 10, font: { size: 11 }, padding: 10 } },
          tooltip: {
            ...COMMON_OPTS.plugins.tooltip,
            callbacks: { label: ctx => ' ' + ctx.label + ': ' + fmtCostExact(ctx.parsed) },
          },
        },
      },
    };
    if (!modelChart) {
      modelChart = new Chart(document.getElementById('model-chart'), cfg);
    } else {
      modelChart.data = cfg.data; modelChart.update();
    }
  }

  /*  Main refresh loop  --------------------------------------------------- */
  async function refresh() {
    let q;
    try {
      const r = await fetch('/quota', { cache: 'no-store' });
      q = await r.json();
      const pill = document.getElementById('status-pill');
      pill.classList.remove('error'); pill.classList.add('live');
      document.getElementById('status-text').textContent = 'live';
      document.getElementById('last-refresh').textContent =
        'updated ' + new Date().toLocaleTimeString();
    } catch (e) {
      const pill = document.getElementById('status-pill');
      pill.classList.add('error'); pill.classList.remove('live');
      document.getElementById('status-text').textContent = 'offline';
      return;
    }

    /* Totals cards */
    const t = q.tokens || {};
    document.getElementById('cost-total').textContent  = fmtCostExact(q.cost_usd_total);
    document.getElementById('req-total').textContent   = fmtCount.format(q.messages_requests || 0);
    document.getElementById('session-count').textContent = fmtCount.format((q.by_session || []).length);
    document.getElementById('in-total').textContent    = fmtCount.format(t.input_tokens || 0);
    document.getElementById('out-total').textContent   = fmtCount.format(t.output_tokens || 0);
    document.getElementById('cache-read').textContent  = fmtCount.format(t.cache_read_input_tokens || 0);
    document.getElementById('cache-write').textContent = fmtCount.format(t.cache_creation_input_tokens || 0);
    document.getElementById('cost-meta').textContent =
      (q.messages_requests || 0) === 0
        ? 'No requests recorded yet'
        : `Across ${fmtCount.format(q.messages_requests)} requests on ${(q.by_model || []).length} model(s)`;

    /* Rate limits */
    const rl = q.rate_limits || {};
    const rlEl = document.getElementById('rate-limits');
    rlEl.innerHTML = '';
    let any = false;
    any |= addBar(rlEl, 'Requests',      rl.requests_remaining,      rl.requests_limit,      rl.requests_reset);
    any |= addBar(rlEl, 'Input tokens',  rl.input_tokens_remaining,  rl.input_tokens_limit,  rl.input_tokens_reset);
    any |= addBar(rlEl, 'Output tokens', rl.output_tokens_remaining, rl.output_tokens_limit, rl.output_tokens_reset);
    any |= addBar(rlEl, 'Total tokens',  rl.tokens_remaining,        rl.tokens_limit,        rl.tokens_reset);
    if (rl.retry_after) {
      const div = document.createElement('div');
      div.className = 'retry-banner';
      div.textContent = '⚠ Anthropic asked us to retry after ' + rl.retry_after + ' s';
      rlEl.appendChild(div);
    }
    if (!any && !rl.retry_after) {
      const div = document.createElement('div');
      div.className = 'empty-bars';
      div.textContent = 'Waiting for first /v1/messages response from Anthropic…';
      rlEl.appendChild(div);
    }

    /* Daily chart + range label + table */
    const days = q.by_day || [];
    if (window.Chart) buildDailyChart(days);
    document.getElementById('daily-range').textContent =
      days.length ? (days[days.length - 1].date + ' → ' + days[0].date) : '';
    const dailyTb = document.querySelector('#daily-table tbody');
    dailyTb.innerHTML = '';
    document.getElementById('daily-empty').style.display = days.length ? 'none' : 'block';
    document.getElementById('daily-table').style.display = days.length ? '' : 'none';
    for (const d of days) {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><span class="num">${d.date}</span></td>
        <td class="num">${fmtCount.format(d.requests)}</td>
        <td class="num">${fmtNum(d.input_tokens)}</td>
        <td class="num">${fmtNum(d.output_tokens)}</td>
        <td class="num">${fmtNum(d.cache_read_input_tokens)}</td>
        <td class="num">${fmtNum(d.cache_creation_input_tokens)}</td>
        <td class="num cost">${fmtCostExact(d.cost_usd)}</td>`;
      dailyTb.appendChild(tr);
    }

    /* Per-model table + chart */
    const models = q.by_model || [];
    if (window.Chart) buildModelChart(models);
    const modelTb = document.querySelector('#model-table tbody');
    modelTb.innerHTML = '';
    document.getElementById('model-empty').style.display = models.length ? 'none' : 'block';
    document.getElementById('model-table').style.display = models.length ? '' : 'none';
    for (const m of models) {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><strong>${m.model}</strong></td>
        <td class="num">${fmtCount.format(m.requests)}</td>
        <td class="num">${fmtNum(m.input_tokens)}</td>
        <td class="num">${fmtNum(m.output_tokens)}</td>
        <td class="num">${fmtNum(m.cache_read_input_tokens)}</td>
        <td class="num">${fmtNum(m.cache_creation_input_tokens)}</td>
        <td class="num cost">${fmtCostExact(m.cost_usd)}</td>`;
      modelTb.appendChild(tr);
    }

    /* Per-session table */
    const sessions = q.by_session || [];
    const sessTb = document.querySelector('#session-table tbody');
    sessTb.innerHTML = '';
    document.getElementById('session-empty').style.display = sessions.length ? 'none' : 'block';
    document.getElementById('session-table').style.display = sessions.length ? '' : 'none';
    for (const s of sessions) {
      const tr = document.createElement('tr');
      const id = s.session_id || '';
      const idHead = id.length > 14 ? id.slice(0, 8) : id;
      const idTail = id.length > 14 ? '…' + id.slice(-4) : '';
      const modelBadges = Object.entries(s.models || {})
        .map(([k, n]) => `<span class="badge">${k} × ${n}</span>`).join('');
      const lastSeen = s.last_seen
        ? `<span class="timestamp">${fmtRelativeTime(s.last_seen)}<small>${s.last_seen.replace('T',' ')}</small></span>`
        : '—';
      tr.innerHTML = `
        <td class="session-id" title="${id}">${idHead}<span class="session-tail">${idTail}</span></td>
        <td>${modelBadges || '<span class="badge">—</span>'}</td>
        <td class="num">${fmtCount.format(s.requests)}</td>
        <td class="num">${fmtNum(s.input_tokens)} / ${fmtNum(s.output_tokens)}</td>
        <td class="num cost">${fmtCostExact(s.cost_usd)}</td>
        <td>${lastSeen}</td>`;
      sessTb.appendChild(tr);
    }
  }

  refresh();
  setInterval(refresh, 5000);
</script>
</body>
</html>
"""


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    return HTMLResponse(content=DASHBOARD_HTML)


@app.get("/quota")
async def quota():
    """Compact quota summary tuned for human display."""
    rl = quota_stats["rate_limits"]

    sessions = sorted(
        quota_stats["by_session"].values(),
        key=lambda s: s.get("last_seen", ""),
        reverse=True,
    )

    days = sorted(
        quota_stats["by_day"].values(),
        key=lambda d: d.get("date", ""),
        reverse=True,
    )[:15]

    summary = {
        "cost_usd_total": round(quota_stats["cost_usd_total"], 4),
        "messages_requests": quota_stats["messages_requests"],
        "tokens": quota_stats["usage_total"],
        "by_model": [
            {
                "model": v["model"],
                "requests": v["requests"],
                "input_tokens": v["input_tokens"],
                "output_tokens": v["output_tokens"],
                "cache_read_input_tokens": v["cache_read_input_tokens"],
                "cache_creation_input_tokens": v["cache_creation_input_tokens"],
                "cost_usd": round(v["cost_usd"], 4),
            }
            for v in quota_stats["by_model"].values()
        ],
        "by_session": [
            {
                "session_id": s["session_id"],
                "requests": s["requests"],
                "input_tokens": s["input_tokens"],
                "output_tokens": s["output_tokens"],
                "cache_read_input_tokens": s["cache_read_input_tokens"],
                "cache_creation_input_tokens": s["cache_creation_input_tokens"],
                "cost_usd": round(s["cost_usd"], 4),
                "models": s.get("models", {}),
                "first_seen": s.get("first_seen"),
                "last_seen": s.get("last_seen"),
            }
            for s in sessions
        ],
        "by_day": [
            {
                "date": d["date"],
                "requests": d["requests"],
                "input_tokens": d["input_tokens"],
                "output_tokens": d["output_tokens"],
                "cache_read_input_tokens": d["cache_read_input_tokens"],
                "cache_creation_input_tokens": d["cache_creation_input_tokens"],
                "cost_usd": round(d["cost_usd"], 4),
            }
            for d in days
        ],
        "rate_limits": {
            "requests_remaining": rl.get("requests-remaining"),
            "requests_limit": rl.get("requests-limit"),
            "requests_reset": rl.get("requests-reset"),
            "input_tokens_remaining": rl.get("input-tokens-remaining"),
            "input_tokens_limit": rl.get("input-tokens-limit"),
            "input_tokens_reset": rl.get("input-tokens-reset"),
            "output_tokens_remaining": rl.get("output-tokens-remaining"),
            "output_tokens_limit": rl.get("output-tokens-limit"),
            "output_tokens_reset": rl.get("output-tokens-reset"),
            "tokens_remaining": rl.get("tokens-remaining"),
            "tokens_limit": rl.get("tokens-limit"),
            "tokens_reset": rl.get("tokens-reset"),
            "retry_after": rl.get("retry-after"),
            "updated_at": quota_stats["rate_limits_updated_at"],
        },
    }
    return summary


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"])
async def proxy(path: str, request: Request):
    global request_count, blocked_requests_count
    request_count += 1
    req_id = request_count

    now = datetime.now().strftime("%H:%M:%S")

    # ── Telemetry blocking ──
    if is_blocked_path(path):
        blocked_requests_count += 1
        log(f"  {DIM}{now}{RESET}  {CYAN}{BOLD}#{req_id}{RESET}  {BG_RED}{BOLD} BLOCKED {RESET} {RED}Telemetry: /{path}{RESET}")
        log("")
        return JSONResponse(
            status_code=200,
            content={"status": "ok"},
        )

    # Auto-capture identity headers, cảnh báo header lạ
    capture_identity_from_request(request)
    warn_unknown_headers(request)

    # ── Request timing jitter ──
    if TIMING_JITTER_ENABLED:
        jitter_ms = random.randint(TIMING_JITTER_MIN_MS, TIMING_JITTER_MAX_MS)
        await _async_sleep(jitter_ms / 1000.0)

    target_url = f"{ANTHROPIC_BASE_URL}/{path}"
    headers = build_request_headers(request)
    body = await request.body()

    # ── Body sanitization ──
    content_type = request.headers.get("content-type", "")
    body = sanitize_body(body, content_type)

    # ── Token saver ──
    if TOKEN_SAVER_ENABLED:
        body = optimize_tokens(body, content_type, path)
        inject_cache_ttl_beta(headers)

    start_time = time.monotonic()

    # Request log
    log(f"  {DIM}{now}{RESET}  {CYAN}{BOLD}#{req_id}{RESET}  {BLUE}{BOLD}{request.method}{RESET} /{path}")

    # Headers log (minimal - don't leak info in logs)
    sensitive = {"authorization", "x-api-key", "cookie"}
    spoofed = set(captured_identity.keys())
    for k, v in headers.items():
        kl = k.lower()
        if kl in sensitive:
            log(f"           {DIM}{k}: {RESET}{YELLOW}[REDACTED]{RESET}")
        elif kl in spoofed:
            log(f"           {DIM}{k}: {RESET}{MAGENTA}{mask_value(v, 20)}{RESET} {DIM}(locked){RESET}")
        else:
            log(f"           {DIM}{k}: {mask_value(v, 30)}{RESET}")

    try:
        req = http_client.build_request(
            method=request.method,
            url=target_url,
            headers=headers,
            content=body,
            params=dict(request.query_params),
        )
        response = await http_client.send(req, stream=True)

        elapsed = time.monotonic() - start_time
        status = response.status_code

        # Capture anthropic-ratelimit-* headers regardless of status.
        _record_rate_limits(response.headers)

        # Read the ORIGINAL session id from the incoming request (before the
        # proxy rewrites the header to the locked identity). Each device's
        # CC session shows up separately in by_session even though all
        # devices share the locked outgoing fingerprint.
        client_session_id = request.headers.get("x-claude-code-session-id")

        # Set up usage tap for /v1/messages (no-op for other paths).
        usage_tap = UsageTap(
            response.headers.get("content-type"),
            path,
            session_id=client_session_id,
        )

        # Buffer 400 bodies so we can detect Anthropic beta-header rejection
        # and latch the cache-ttl beta off for subsequent requests.
        buffered_body: bytes | None = None
        if (
            status == 400
            and TOKEN_SAVER_ENABLED
            and CACHE_EXTEND_TTL
            and not _cache_ttl_runtime_disabled
        ):
            try:
                buffered_body = await response.aread()
            finally:
                await response.aclose()
            if _looks_like_cache_ttl_beta_error(buffered_body):
                disable_cache_ttl_runtime("upstream rejected extended-cache-ttl beta")

        if 200 <= status < 300:
            status_str = f"{BG_GREEN}{BOLD} {status} {RESET}"
        elif status == 401:
            status_str = f"{BG_RED}{BOLD} {status} UNAUTHORIZED {RESET}"
            log(f"           {RED}{BOLD}TOKEN HET HAN! Login lai tren 1 may bat ky{RESET}")
        elif status == 429:
            status_str = f"{BG_YELLOW}{BOLD} {status} RATE LIMITED {RESET}"
            retry_after = quota_stats["rate_limits"].get("retry-after")
            if retry_after:
                log(f"           {YELLOW}Rate limited - retry-after: {retry_after}s{RESET}")
            else:
                log(f"           {YELLOW}Qua nhieu request - doi mot chut...{RESET}")
        elif 400 <= status < 500:
            status_str = f"{BG_YELLOW}{BOLD} {status} {RESET}"
        else:
            status_str = f"{BG_RED}{BOLD} {status} {RESET}"

        log(f"  {DIM}{now}{RESET}  {CYAN}{BOLD}#{req_id}{RESET}  {status_str} {DIM}{elapsed:.1f}s{RESET}")
        log("")

        response_headers = filter_response_headers(response)

        # Strip Set-Cookie from responses to prevent cookie-based tracking
        response_headers = {
            k: v for k, v in response_headers.items()
            if k.lower() != "set-cookie"
        }

        if buffered_body is not None:
            # Even on 400 we still try to extract usage if present (rare but
            # harmless), so the tap sees the body too.
            usage_tap.feed(buffered_body)
            model, usage = usage_tap.finalize()
            if usage:
                _record_usage(model, usage, usage_tap.session_id)
            return Response(
                content=buffered_body,
                status_code=response.status_code,
                headers=response_headers,
                media_type=response.headers.get("content-type"),
            )

        async def stream_response():
            try:
                async for chunk in response.aiter_bytes():
                    usage_tap.feed(chunk)
                    yield chunk
            finally:
                await response.aclose()
                model, usage = usage_tap.finalize()
                if usage:
                    _record_usage(model, usage, usage_tap.session_id)

        return StreamingResponse(
            stream_response(),
            status_code=response.status_code,
            headers=response_headers,
            media_type=response.headers.get("content-type"),
        )

    except httpx.TimeoutException:
        log(f"  {DIM}{now}{RESET}  {CYAN}{BOLD}#{req_id}{RESET}  {BG_RED}{BOLD} TIMEOUT {RESET}")
        log("")
        raise HTTPException(status_code=504, detail="Gateway timeout")
    except httpx.ConnectError:
        log(f"  {DIM}{now}{RESET}  {CYAN}{BOLD}#{req_id}{RESET}  {BG_RED}{BOLD} CONNECT ERROR {RESET}")
        log("")
        raise HTTPException(status_code=502, detail="Bad gateway")
    except Exception:
        # Don't leak internal error details
        log(f"  {DIM}{now}{RESET}  {CYAN}{BOLD}#{req_id}{RESET}  {BG_RED}{BOLD} ERROR {RESET}")
        log("")
        raise HTTPException(status_code=500, detail="Internal proxy error")


async def _async_sleep(seconds: float):
    """Async sleep for timing jitter."""
    await asyncio.sleep(seconds)


if __name__ == "__main__":
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=LOCAL_PORT,
        log_level="warning",
        # Don't expose server header
        server_header=False,
        date_header=False,
    )
