"""Every operator-tunable value, resolved from the environment at import time.

INVARIANT: this module owns all config scalars, and consumers must read them as
attributes (``settings.TIMING_JITTER_MAX_MS``), never via ``from .settings
import TIMING_JITTER_MAX_MS``. The ``/config`` console live-patches values with
``setattr(settings, ...)``; a value copied into another module at import time
would silently ignore those edits.
"""

from __future__ import annotations

import ipaddress
import re
import secrets
import socket
import sys

from .env import data_path, env_bool, env_float, env_int, env_str

# ============================================================
# SERVER / UPSTREAM
# ============================================================
LOCAL_PORT = env_int("LOCAL_PORT", 9999)

# Upstream API root. Overridable so the proxy can be pointed at a local echo
# server (or a corporate gateway) without touching code.
ANTHROPIC_BASE_URL = env_str("ANTHROPIC_UPSTREAM_URL", "https://api.anthropic.com").rstrip("/")

# Development-only: answer /v1/* locally with a synthetic Anthropic-shaped
# response instead of calling any upstream at all. Exercises the whole
# sanitize/token-saver/quota/coach pipeline offline. Never enable in production.
DEV_ECHO_MODE = env_bool("DEV_ECHO_MODE", False)
DEV_ECHO_MODEL = env_str("DEV_ECHO_MODEL", "claude-sonnet-5-echo")
DEV_ECHO_LATENCY_MS = env_int("DEV_ECHO_LATENCY_MS", 0)
DEV_ECHO_INPUT_TOKENS = env_int("DEV_ECHO_INPUT_TOKENS", 1200)
DEV_ECHO_OUTPUT_TOKENS = env_int("DEV_ECHO_OUTPUT_TOKENS", 64)
DEV_ECHO_CACHE_READ_TOKENS = env_int("DEV_ECHO_CACHE_READ_TOKENS", 0)
DEV_ECHO_CACHE_WRITE_TOKENS = env_int("DEV_ECHO_CACHE_WRITE_TOKENS", 0)

# ============================================================
# DEPLOY MODE
#   local  — bind 127.0.0.1, no IP whitelist, identity auto-captured.
#            Each device runs its own proxy (original behaviour).
#   server — bind LOCAL_HOST (default 0.0.0.0) so other machines can reach it,
#            require ALLOWED_IPS, identity must be pre-populated in .env
#            (auto-capture is disabled so random first caller can't lock it).
# ============================================================
DEPLOY_MODE = env_str("DEPLOY_MODE", "local").lower()
if DEPLOY_MODE not in ("local", "server"):
    DEPLOY_MODE = "local"
LOCAL_HOST = (
    env_str("LOCAL_HOST", "0.0.0.0" if DEPLOY_MODE == "server" else "127.0.0.1") or "127.0.0.1"
)


def parse_allowed_networks(raw: str) -> list:
    """Parse a comma-separated list of IPs / CIDR blocks (v4 + v6)."""
    nets = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            if "/" in token:
                nets.append(ipaddress.ip_network(token, strict=False))
            else:
                addr = ipaddress.ip_address(token)
                prefix = 32 if isinstance(addr, ipaddress.IPv4Address) else 128
                nets.append(ipaddress.ip_network(f"{addr}/{prefix}", strict=False))
        except ValueError:
            print(f"  [WARN] Invalid ALLOWED_IPS entry ignored: {token!r}", file=sys.stderr)
    return nets


ALLOWED_IPS_RAW = env_str("ALLOWED_IPS")
ALLOWED_NETWORKS = parse_allowed_networks(ALLOWED_IPS_RAW)

# Admin-only endpoints (e.g. /admin/quota/reset/*) require the caller to come
# from one of these IPs. Defaults to loopback so the VM operator can curl them
# but no remote whitelisted client can reset other users' caps.
ADMIN_IPS = {ip.strip() for ip in env_str("ADMIN_IPS", "127.0.0.1,::1").split(",") if ip.strip()}

# Stats endpoints (/health, /quota, /quota/users, /quota/users/{label},
# /dashboard) can leak per-user spend info. STATS_PRIVATE=true gates them to
# STATS_VIEW_IPS only. Defaults to ADMIN_IPS when not explicitly set.
STATS_PRIVATE = env_bool("STATS_PRIVATE", False)
_stats_ips_raw = env_str("STATS_VIEW_IPS")
if _stats_ips_raw:
    STATS_VIEW_IPS = {ip.strip() for ip in _stats_ips_raw.split(",") if ip.strip()}
else:
    STATS_VIEW_IPS = set(ADMIN_IPS)

# Paths gated by STATS_PRIVATE. Prefix entries end with "/".
STATS_PATHS = ("/health", "/quota", "/quota/users", "/dashboard", "/coach")
STATS_PATH_PREFIXES = ("/quota/users/",)

# ============================================================
# IDENTITY
# ============================================================
# When set, only this exact IP may lock the device identity on the first
# request (server mode only). Empty = any whitelisted IP can be the capturer.
CAPTURE_LOCK_FROM_IP = env_str("CAPTURE_LOCK_FROM_IP")

# Auto-refresh the locked identity every N days. 0 disables (lock forever).
IDENTITY_REFRESH_DAYS = env_int("IDENTITY_REFRESH_DAYS", 14)

# User-agent prefix a request must carry before it is allowed to lock identity.
CAPTURE_REQUIRED_UA_PREFIX = env_str("CAPTURE_REQUIRED_UA_PREFIX", "claude-cli/")
# Path (relative, no leading slash) whose requests may capture identity.
CAPTURE_TRIGGER_PATH = env_str("CAPTURE_TRIGGER_PATH", "v1/messages")

# ============================================================
# IP -> USER LABEL MAP
# Format: IP_LABELS=203.0.113.5:phong,2001:db8::1:huy
# rsplit on the last colon so IPv6 addresses parse correctly.
# ============================================================
IP_LABEL_MAP: dict = {}
for _pair in env_str("IP_LABELS").split(","):
    _pair = _pair.strip()
    if ":" not in _pair:
        continue
    _ip, _label = _pair.rsplit(":", 1)
    _ip, _label = _ip.strip(), _label.strip()
    if not _ip or not _label:
        continue
    try:
        IP_LABEL_MAP[ipaddress.ip_address(_ip)] = _label
    except ValueError:
        print(f"  [WARN] Invalid IP_LABELS entry ignored: {_pair!r}", file=sys.stderr)

# ============================================================
# PER-USER QUOTA (per source IP / URL prefix)
# ============================================================
USER_QUOTA_ENABLED = env_bool("USER_QUOTA_ENABLED", False)
USER_QUOTA_PERIOD = env_str("USER_QUOTA_PERIOD", "monthly").lower()
if USER_QUOTA_PERIOD not in ("daily", "monthly"):
    USER_QUOTA_PERIOD = "monthly"
USER_QUOTA_DEFAULT_USD = env_float("USER_QUOTA_DEFAULT_USD", 0.0)
USER_QUOTA_HARD_LIMIT = env_bool("USER_QUOTA_HARD_LIMIT", True)

USER_QUOTA_CAPS: dict[str, float] = {}
for _pair in env_str("USER_QUOTA_CAPS").split(","):
    _pair = _pair.strip()
    if ":" not in _pair:
        continue
    _label, _cap = _pair.split(":", 1)
    try:
        USER_QUOTA_CAPS[_label.strip()] = float(_cap.strip())
    except ValueError:
        print(f"  [WARN] Invalid USER_QUOTA_CAPS entry ignored: {_pair!r}", file=sys.stderr)

# Allowed character set for URL-prefix user labels — restricted so a label
# cannot inject path traversal or query strings into the upstream URL.
USER_LABEL_PATTERN = env_str("USER_LABEL_PATTERN", r"[A-Za-z0-9._-]{1,64}")
USER_LABEL_RE = re.compile(rf"^/u/({USER_LABEL_PATTERN})(/.*)?$")

# ============================================================
# SESSION SECRET (deterministic ID derivation across devices)
# ============================================================
SESSION_SECRET = env_str("SESSION_SECRET")
if not SESSION_SECRET:
    SESSION_SECRET = secrets.token_hex(32)

# ============================================================
# REQUEST TIMING JITTER
# ============================================================
TIMING_JITTER_ENABLED = env_bool("TIMING_JITTER", True)
TIMING_JITTER_MIN_MS = env_int("TIMING_JITTER_MIN_MS", 10)
TIMING_JITTER_MAX_MS = env_int("TIMING_JITTER_MAX_MS", 150)

# ============================================================
# TOKEN SAVER
#   1. CACHE_EXTEND_TTL: bump prompt-cache TTL 5m -> 1h on the stable prefix
#      (system block + last tool definition), via the Anthropic beta header.
#   2. TOOL_RESULT_TRUNCATE: head+tail truncate large tool_result blocks in
#      OLDER turns; recent turns stay intact so the agent loop is unharmed.
# ============================================================
TOKEN_SAVER_ENABLED = env_bool("TOKEN_SAVER", False)
CACHE_EXTEND_TTL = env_bool("CACHE_EXTEND_TTL", True)
TOOL_RESULT_TRUNCATE = env_bool("TOOL_RESULT_TRUNCATE", False)
TOOL_RESULT_MAX_BYTES = env_int("TOOL_RESULT_MAX_BYTES", 8000)
TOOL_RESULT_HEAD_BYTES = env_int("TOOL_RESULT_HEAD_BYTES", 4000)
TOOL_RESULT_TAIL_BYTES = env_int("TOOL_RESULT_TAIL_BYTES", 2000)
TOOL_RESULT_KEEP_RECENT = env_int("TOOL_RESULT_KEEP_RECENT", 2)

CACHE_TTL_BETA = env_str("CACHE_TTL_BETA", "extended-cache-ttl-2025-04-11")
CACHE_TTL_LONG = env_str("CACHE_TTL_LONG", "1h")
MAX_CACHE_BREAKPOINTS = env_int("MAX_CACHE_BREAKPOINTS", 4)
CHARS_PER_TOKEN = env_int("CHARS_PER_TOKEN", 4)

# ============================================================
# QUOTA / COST TRACKING
# ============================================================
QUOTA_TRACKING_ENABLED = env_bool("QUOTA_TRACKING", True)
QUOTA_MAX_SESSIONS = env_int("QUOTA_MAX_SESSIONS", 100)
QUOTA_MAX_DAYS = env_int("QUOTA_MAX_DAYS", 30)
QUOTA_MONTHLY_RESET = env_bool("QUOTA_MONTHLY_RESET", True)

QUOTA_PERSIST_PATH = data_path(".quota.json", env_str("QUOTA_PERSIST_PATH"))
QUOTA_PERSIST_INTERVAL_SECONDS = env_int("QUOTA_PERSIST_INTERVAL", 30)
QUOTA_SCHEMA_VERSION = 4  # v1=base, v2 +by_session+by_day, v3 +by_user, v4 +by_day_user+user.models
QUOTA_SCHEMA_MIN_LOAD = 1  # accept v1+ files for forward migration

# Cap on how many bytes the usage extractor buffers per response, so a
# malformed upstream stream cannot grow memory without bound.
USAGE_TAP_MAX_BUFFER = env_int("USAGE_TAP_MAX_BUFFER", 5 * 1024 * 1024)

# ============================================================
# UPSTREAM CONNECTION TUNING
# Sized for a shared proxy: every SSE response holds its connection for a whole
# turn, so a small pool makes later requests queue silently — which the client
# reports as a stalled response. Pool timeout is short and loud on purpose.
# ============================================================
UPSTREAM_MAX_CONNECTIONS = env_int("UPSTREAM_MAX_CONNECTIONS", 100)
UPSTREAM_MAX_KEEPALIVE = env_int("UPSTREAM_MAX_KEEPALIVE", 20)
UPSTREAM_KEEPALIVE_EXPIRY = env_float("UPSTREAM_KEEPALIVE_EXPIRY", 30)
UPSTREAM_CONNECT_TIMEOUT = env_float("UPSTREAM_CONNECT_TIMEOUT", 10)
UPSTREAM_READ_TIMEOUT = env_float("UPSTREAM_READ_TIMEOUT", 300)
UPSTREAM_POOL_TIMEOUT = env_float("UPSTREAM_POOL_TIMEOUT", 30)
# Fail a stream that receives no bytes for this long; 0 disables the watchdog.
UPSTREAM_STALL_SECONDS = env_float("UPSTREAM_STALL_SECONDS", 120)
# Retry a transport failure only while no byte has been forwarded yet.
UPSTREAM_CONNECT_RETRIES = env_int("UPSTREAM_CONNECT_RETRIES", 2)
UPSTREAM_RETRY_BACKOFF_SECONDS = env_float("UPSTREAM_RETRY_BACKOFF_SECONDS", 0.25)
# Pool contention is only worth reporting past this wait.
UPSTREAM_POOL_WAIT_WARN_MS = env_float("UPSTREAM_POOL_WAIT_WARN_MS", 1000)

# Telemetry client (Loki pushes) — deliberately a tiny separate pool so a slow
# log endpoint cannot starve API traffic.
TELEMETRY_MAX_CONNECTIONS = env_int("TELEMETRY_MAX_CONNECTIONS", 4)
TELEMETRY_MAX_KEEPALIVE = env_int("TELEMETRY_MAX_KEEPALIVE", 2)
TELEMETRY_CONNECT_TIMEOUT = env_float("TELEMETRY_CONNECT_TIMEOUT", 5)
TELEMETRY_POOL_TIMEOUT = env_float("TELEMETRY_POOL_TIMEOUT", 5)

# ============================================================
# LOKI LOG SHIPPING (optional)
# ============================================================
LOKI_URL = env_str("LOKI_URL")
LOKI_ENABLED = bool(LOKI_URL)
LOKI_JOB = env_str("LOKI_JOB", "claude-cloak") or "claude-cloak"
LOKI_HOST = env_str("LOKI_HOST") or socket.gethostname() or "unknown"
LOKI_USER_EMAIL = env_str("LOKI_USER_EMAIL")
LOKI_LABELS_RAW = env_str("LOKI_LABELS")
LOKI_BATCH_SIZE = max(1, env_int("LOKI_BATCH_SIZE", 100))
LOKI_FLUSH_INTERVAL_SECONDS = max(0.5, env_float("LOKI_FLUSH_INTERVAL", 5))
LOKI_MAX_BUFFER = max(LOKI_BATCH_SIZE, env_int("LOKI_MAX_BUFFER", 2000))
LOKI_TIMEOUT_SECONDS = env_float("LOKI_TIMEOUT", 10)
# Seconds between "Loki push failed" warnings, and shutdown flush attempts.
LOKI_WARN_INTERVAL_SECONDS = env_float("LOKI_WARN_INTERVAL", 60)
LOKI_SHUTDOWN_FLUSHES = env_int("LOKI_SHUTDOWN_FLUSHES", 5)

LOKI_EXTRA_LABELS: dict[str, str] = {}
if LOKI_LABELS_RAW:
    for _pair in LOKI_LABELS_RAW.split(","):
        _pair = _pair.strip()
        if "=" in _pair:
            _k, _v = _pair.split("=", 1)
            if _k.strip() and _v.strip():
                LOKI_EXTRA_LABELS[_k.strip()] = _v.strip()

# ============================================================
# CODING COACH (counts only — never prompt text, code or paths)
# ============================================================
COACH_ENABLED = env_bool("COACH_ENABLED", True)
COACH_PERSIST_PATH = data_path(".coach.json", env_str("COACH_PERSIST_PATH"))
COACH_SCHEMA_VERSION = 1

# ============================================================
# CONFIG CONSOLE (/config)
# ============================================================
ADMIN_TOKEN = env_str("ADMIN_TOKEN")
ADMIN_SESSION_HOURS = env_float("ADMIN_SESSION_HOURS", 12)
ADMIN_MAX_FAILED = env_int("ADMIN_MAX_FAILED", 5)
ADMIN_LOCKOUT_SECONDS = env_float("ADMIN_LOCKOUT_SECONDS", 300)
ADMIN_COOKIE_NAME = env_str("ADMIN_COOKIE_NAME", "cloak_admin")
