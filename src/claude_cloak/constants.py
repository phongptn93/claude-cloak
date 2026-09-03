"""Static tables: telemetry paths, body-sanitize fields, header policies.

Each table has an env hook so an operator can extend or replace it without a
code change: ``<NAME>_EXTRA`` adds entries, ``<NAME>_OVERRIDE`` replaces the
list entirely. Both are comma-separated.
"""

from __future__ import annotations

import re

from .env import env_list

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
    "machine_id",
    "machineId",
    "machine-id",
    "device_id",
    "deviceId",
    "device-id",
    "hostname",
    "host_name",
    "computer_name",
    "computerName",
    "username",
    "user_name",
    "userName",
    "home_dir",
    "homeDir",
    "home_directory",
    "os_version",
    "osVersion",
    "os_release",
    "osRelease",
    "platform_version",
    "platformVersion",
    "mac_address",
    "macAddress",
    "hardware_id",
    "hardwareId",
    "installation_id",
    "installationId",
    "instance_id",
    "instanceId",
    "client_id",
    "clientId",
    "workspace_id",
    "workspaceId",
    "vscode_machine_id",
    "vscodeMachineId",
    "vscode_session_id",
    "vscodeSessionId",
}

# Nested objects/paths that could contain device info
SANITIZE_BODY_OBJECTS = {
    "system_info",
    "systemInfo",
    "device_info",
    "deviceInfo",
    "machine_info",
    "machineInfo",
    "environment_info",
    "environmentInfo",
    "telemetry",
    "diagnostics",
}

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
    "content-length",
    "transfer-encoding",
    "content-encoding",
    "connection",
    "keep-alive",
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
_KNOWN_HEADERS_BASE = {
    # Excluded từ forward
    "host",
    "content-length",
    "transfer-encoding",
    # Sensitive / pass-through
    "authorization",
    "x-api-key",
    "cookie",
    # Common HTTP
    "content-type",
    "accept",
    "connection",
    "cache-control",
    "x-request-id",
    "x-forwarded-for",
    "x-real-ip",
    "traceparent",
    "tracestate",
    "pragma",
    "upgrade-insecure-requests",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "dnt",
    "tk",
}

# Headers never forwarded upstream verbatim (hop-by-hop / length bound).
EXCLUDED_REQUEST_HEADERS = {
    "host",
    "content-length",
    "transfer-encoding",
}

# Tool-name buckets for the coach's read-before-edit metric. Names cover
# Claude Code's built-ins plus common aliases from other harnesses.
COACH_EDIT_TOOLS = {
    "Edit",
    "Write",
    "MultiEdit",
    "NotebookEdit",
    "str_replace_editor",
    "create_file",
    "apply_patch",
}
COACH_READ_TOOLS = {"Read", "NotebookRead", "view"}


def _apply_env_hooks(name: str, values):
    """Apply ``<name>_OVERRIDE`` / ``<name>_EXTRA`` to a table."""
    override = env_list(f"{name}_OVERRIDE")
    base = override if override else list(values)
    base += [item for item in env_list(f"{name}_EXTRA") if item not in base]
    return type(values)(base) if isinstance(values, (set, frozenset)) else base


BLOCKED_PATH_PATTERNS = _apply_env_hooks("BLOCKED_PATH_PATTERNS", BLOCKED_PATH_PATTERNS)
BLOCKED_PATH_REGEX = [re.compile(p, re.IGNORECASE) for p in BLOCKED_PATH_PATTERNS]
SANITIZE_BODY_FIELDS = _apply_env_hooks("SANITIZE_BODY_FIELDS", SANITIZE_BODY_FIELDS)
SANITIZE_BODY_OBJECTS = _apply_env_hooks("SANITIZE_BODY_OBJECTS", SANITIZE_BODY_OBJECTS)
CAPTURE_HEADERS = _apply_env_hooks("CAPTURE_HEADERS", CAPTURE_HEADERS)
STRIP_REQUEST_HEADERS = _apply_env_hooks("STRIP_REQUEST_HEADERS", STRIP_REQUEST_HEADERS)
STRIP_RESPONSE_HEADERS = _apply_env_hooks("STRIP_RESPONSE_HEADERS", STRIP_RESPONSE_HEADERS)
KNOWN_HEADERS = _apply_env_hooks(
    "KNOWN_HEADERS",
    {h.lower() for h in CAPTURE_HEADERS} | set(STRIP_REQUEST_HEADERS) | _KNOWN_HEADERS_BASE,
)
EXCLUDED_REQUEST_HEADERS = _apply_env_hooks("EXCLUDED_REQUEST_HEADERS", EXCLUDED_REQUEST_HEADERS)
COACH_EDIT_TOOLS = _apply_env_hooks("COACH_EDIT_TOOLS", COACH_EDIT_TOOLS)
COACH_READ_TOOLS = _apply_env_hooks("COACH_READ_TOOLS", COACH_READ_TOOLS)

# Pre-computed normalized sets for fast lookup during body sanitization
_SANITIZE_FIELDS_NORMALIZED = {s.lower().replace("-", "_") for s in SANITIZE_BODY_FIELDS}
_SANITIZE_OBJECTS_NORMALIZED = {s.lower().replace("-", "_") for s in SANITIZE_BODY_OBJECTS}
