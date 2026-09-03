"""/config console: setting specs, current values, and safe application."""

from __future__ import annotations

import os

from . import settings
from .env import ENV_PATH, save_to_env
from .pricing import PRICING
from .terminal import BG_GREEN, BOLD, GREEN, RESET, log

CONFIG_SPECS: list[dict] = [
    # ---- Stream health / upstream ----
    {
        "key": "UPSTREAM_STALL_SECONDS",
        "var": "UPSTREAM_STALL_SECONDS",
        "type": "float",
        "scope": "live",
        "section": "Stream health",
        "min": 0,
        "max": 3600,
        "desc": "End a stream that receives no bytes for this long and send the client a proper SSE error. 0 disables.",
    },
    {
        "key": "UPSTREAM_CONNECT_RETRIES",
        "var": "UPSTREAM_CONNECT_RETRIES",
        "type": "int",
        "scope": "live",
        "section": "Stream health",
        "min": 0,
        "max": 10,
        "desc": "Retries for a transport failure, only while no byte has been forwarded yet.",
    },
    {
        "key": "UPSTREAM_MAX_CONNECTIONS",
        "var": "UPSTREAM_MAX_CONNECTIONS",
        "type": "int",
        "scope": "restart",
        "section": "Stream health",
        "min": 1,
        "max": 1000,
        "desc": "Upstream connection pool size. Too small and concurrent requests queue silently, which clients report as a stall.",
    },
    {
        "key": "UPSTREAM_MAX_KEEPALIVE",
        "var": "UPSTREAM_MAX_KEEPALIVE",
        "type": "int",
        "scope": "restart",
        "section": "Stream health",
        "min": 0,
        "max": 1000,
        "desc": "Idle connections kept alive for reuse.",
    },
    {
        "key": "UPSTREAM_POOL_TIMEOUT",
        "var": "UPSTREAM_POOL_TIMEOUT",
        "type": "float",
        "scope": "restart",
        "section": "Stream health",
        "min": 1,
        "max": 600,
        "desc": "How long a request waits for a free pool slot before failing loudly.",
    },
    {
        "key": "UPSTREAM_READ_TIMEOUT",
        "var": "UPSTREAM_READ_TIMEOUT",
        "type": "float",
        "scope": "restart",
        "section": "Stream health",
        "min": 1,
        "max": 3600,
        "desc": "Bound on a single silent read from upstream.",
    },
    {
        "key": "UPSTREAM_CONNECT_TIMEOUT",
        "var": "UPSTREAM_CONNECT_TIMEOUT",
        "type": "float",
        "scope": "restart",
        "section": "Stream health",
        "min": 1,
        "max": 120,
        "desc": "TCP/TLS connect timeout to Anthropic.",
    },
    # ---- Anonymity ----
    {
        "key": "TIMING_JITTER",
        "var": "TIMING_JITTER_ENABLED",
        "type": "bool",
        "scope": "live",
        "section": "Anonymity",
        "desc": "Random per-request delay so simultaneous multi-device traffic doesn't look like one machine.",
    },
    {
        "key": "TIMING_JITTER_MIN_MS",
        "var": "TIMING_JITTER_MIN_MS",
        "type": "int",
        "scope": "live",
        "section": "Anonymity",
        "min": 0,
        "max": 5000,
        "desc": "Lower bound of the jitter window.",
    },
    {
        "key": "TIMING_JITTER_MAX_MS",
        "var": "TIMING_JITTER_MAX_MS",
        "type": "int",
        "scope": "live",
        "section": "Anonymity",
        "min": 0,
        "max": 5000,
        "desc": "Upper bound of the jitter window.",
    },
    {
        "key": "IDENTITY_REFRESH_DAYS",
        "var": "IDENTITY_REFRESH_DAYS",
        "type": "int",
        "scope": "live",
        "section": "Anonymity",
        "min": 0,
        "max": 365,
        "desc": "Re-capture the locked identity fingerprint after this many days. 0 keeps it forever.",
    },
    {
        "key": "CAPTURE_LOCK_FROM_IP",
        "type": "str",
        "scope": "locked",
        "section": "Anonymity",
        "desc": "Only this IP may set the locked identity. Locked: it controls whose fingerprint everyone else inherits.",
    },
    # ---- Token saver ----
    {
        "key": "TOKEN_SAVER",
        "var": "TOKEN_SAVER_ENABLED",
        "type": "bool",
        "scope": "live",
        "section": "Token saver",
        "desc": "Master switch for input-token reduction on /v1/messages.",
    },
    {
        "key": "CACHE_EXTEND_TTL",
        "var": "CACHE_EXTEND_TTL",
        "type": "bool",
        "scope": "live",
        "section": "Token saver",
        "desc": "Bump the prompt-cache TTL from 5m to 1h on the stable prefix.",
    },
    {
        "key": "TOOL_RESULT_TRUNCATE",
        "var": "TOOL_RESULT_TRUNCATE",
        "type": "bool",
        "scope": "live",
        "section": "Token saver",
        "desc": "Trim oversized tool results before they are re-sent as context.",
    },
    {
        "key": "TOOL_RESULT_MAX_BYTES",
        "var": "TOOL_RESULT_MAX_BYTES",
        "type": "int",
        "scope": "live",
        "section": "Token saver",
        "min": 1000,
        "max": 10_000_000,
        "desc": "Size above which a tool result is trimmed.",
    },
    {
        "key": "TOOL_RESULT_KEEP_RECENT",
        "var": "TOOL_RESULT_KEEP_RECENT",
        "type": "int",
        "scope": "live",
        "section": "Token saver",
        "min": 0,
        "max": 100,
        "desc": "Most recent tool results left untouched.",
    },
    # ---- Quota & cost ----
    {
        "key": "QUOTA_TRACKING",
        "var": "QUOTA_TRACKING_ENABLED",
        "type": "bool",
        "scope": "live",
        "section": "Quota & cost",
        "desc": "Record token usage and estimated cost per request.",
    },
    {
        "key": "QUOTA_PERSIST_INTERVAL",
        "var": "QUOTA_PERSIST_INTERVAL_SECONDS",
        "type": "int",
        "scope": "live",
        "section": "Quota & cost",
        "min": 0,
        "max": 3600,
        "desc": "Debounce between writes of .quota.json. 0 writes on every response.",
    },
    {
        "key": "QUOTA_MAX_SESSIONS",
        "var": "QUOTA_MAX_SESSIONS",
        "type": "int",
        "scope": "live",
        "section": "Quota & cost",
        "min": 1,
        "max": 10000,
        "desc": "Per-session buckets kept before the oldest are evicted.",
    },
    {
        "key": "QUOTA_MAX_DAYS",
        "var": "QUOTA_MAX_DAYS",
        "type": "int",
        "scope": "live",
        "section": "Quota & cost",
        "min": 1,
        "max": 3650,
        "desc": "Days of history kept for the trend chart.",
    },
    {
        "key": "QUOTA_MONTHLY_RESET",
        "var": "QUOTA_MONTHLY_RESET",
        "type": "bool",
        "scope": "live",
        "section": "Quota & cost",
        "desc": "Zero the running totals at the start of each calendar month.",
    },
    {
        "key": "PRICING_FALLBACK_INPUT",
        "type": "float",
        "scope": "restart",
        "section": "Quota & cost",
        "min": 0,
        "max": 1000,
        "desc": "Input rate applied to a model id matching no pricing key (see unpriced_models in /quota).",
    },
    {
        "key": "PRICING_FALLBACK_OUTPUT",
        "type": "float",
        "scope": "restart",
        "section": "Quota & cost",
        "min": 0,
        "max": 1000,
        "desc": "Output rate for the same fallback path.",
    },
    # ---- Per-user quota ----
    {
        "key": "USER_QUOTA_ENABLED",
        "var": "USER_QUOTA_ENABLED",
        "type": "bool",
        "scope": "live",
        "section": "Per-user quota",
        "desc": "Track and optionally cap spend per user label.",
    },
    {
        "key": "USER_QUOTA_HARD_LIMIT",
        "var": "USER_QUOTA_HARD_LIMIT",
        "type": "bool",
        "scope": "live",
        "section": "Per-user quota",
        "desc": "Reject requests with 429 once a user is over cap. Off = track only.",
    },
    {
        "key": "USER_QUOTA_DEFAULT_USD",
        "var": "USER_QUOTA_DEFAULT_USD",
        "type": "float",
        "scope": "live",
        "section": "Per-user quota",
        "min": 0,
        "max": 100000,
        "desc": "Cap applied to a user with no explicit entry in USER_QUOTA_CAPS.",
    },
    {
        "key": "USER_QUOTA_PERIOD",
        "type": "str",
        "scope": "restart",
        "section": "Per-user quota",
        "choices": ["day", "week", "month"],
        "desc": "Window the per-user cap resets on.",
    },
    {
        "key": "USER_QUOTA_CAPS",
        "type": "str",
        "scope": "restart",
        "section": "Per-user quota",
        "desc": "Per-user overrides, e.g. phong=50,nam=20.",
    },
    # ---- Coaching ----
    {
        "key": "COACH_ENABLED",
        "var": "COACH_ENABLED",
        "type": "bool",
        "scope": "live",
        "section": "Coaching",
        "desc": "Derive privacy-safe practice insights from traffic already passing through (counts only).",
    },
    # ---- Access control (locked) ----
    {
        "key": "DEPLOY_MODE",
        "type": "str",
        "scope": "locked",
        "section": "Access control",
        "desc": "local or server. Locked: it decides whether the IP whitelist is enforced at all.",
    },
    {
        "key": "ALLOWED_IPS",
        "type": "str",
        "scope": "locked",
        "section": "Access control",
        "desc": "Who may use the proxy. Locked: web-editable would let one leaked token grant permanent access.",
    },
    {
        "key": "ADMIN_IPS",
        "type": "str",
        "scope": "locked",
        "section": "Access control",
        "desc": "Who may reach /admin and /config. Locked for the same reason.",
    },
    {
        "key": "STATS_PRIVATE",
        "type": "str",
        "scope": "locked",
        "section": "Access control",
        "desc": "Gate the stats endpoints to STATS_VIEW_IPS.",
    },
    {
        "key": "STATS_VIEW_IPS",
        "type": "str",
        "scope": "locked",
        "section": "Access control",
        "desc": "Who may see per-user spend.",
    },
    {
        "key": "IP_LABELS",
        "type": "str",
        "scope": "locked",
        "section": "Access control",
        "desc": "IP-to-user-label mapping used for cost attribution.",
    },
    {
        "key": "ADMIN_TOKEN",
        "var": "ADMIN_TOKEN",
        "type": "str",
        "scope": "locked",
        "section": "Access control",
        "secret": True,
        "desc": "Password for this console. Locked: it is the credential being checked.",
    },
    # var is set so presence reflects the in-process value: SESSION_SECRET is
    # auto-generated at startup when absent from .env, and reporting it as
    # "not set" would wrongly suggest cookies are unsigned.
    {
        "key": "SESSION_SECRET",
        "var": "SESSION_SECRET",
        "type": "str",
        "scope": "locked",
        "section": "Access control",
        "secret": True,
        "desc": "HMAC key for consistent IDs and admin cookies. Auto-generated at startup if absent, which invalidates admin sessions on every restart — set it in .env to keep them across restarts.",
    },
    {
        "key": "LOCAL_PORT",
        "type": "str",
        "scope": "locked",
        "section": "Access control",
        "desc": "Listen port. Changing it from the web would strand the console.",
    },
    # ---- Telemetry shipping ----
    {
        "key": "LOKI_URL",
        "type": "str",
        "scope": "restart",
        "section": "Telemetry",
        "secret": True,
        "desc": "Grafana Loki push endpoint. Empty disables shipping. Treated as a secret — it can embed credentials.",
    },
    {
        "key": "LOKI_BATCH_SIZE",
        "type": "int",
        "scope": "restart",
        "section": "Telemetry",
        "min": 1,
        "max": 10000,
        "desc": "Entries per push.",
    },
    {
        "key": "LOKI_FLUSH_INTERVAL",
        "type": "float",
        "scope": "restart",
        "section": "Telemetry",
        "min": 1,
        "max": 3600,
        "desc": "Seconds between flushes.",
    },
    {
        "key": "LOKI_USER_EMAIL",
        "type": "str",
        "scope": "restart",
        "section": "Telemetry",
        "secret": True,
        "desc": "Optional Loki label. Treated as a secret — it is personal data.",
    },
]

CONFIG_INDEX = {s["key"]: s for s in CONFIG_SPECS}
CONFIG_SECTIONS = list(dict.fromkeys(s["section"] for s in CONFIG_SPECS))


def _config_current_value(spec: dict):
    """Effective value right now — the live setting when the spec names one.

    INV-1: settings own every editable scalar, so this reads (and _config_apply
    writes) through the settings module rather than this module's globals.
    """
    var = spec.get("var")
    if var and hasattr(settings, var):
        return getattr(settings, var)
    return os.getenv(spec["key"], "")


def _config_coerce(spec: dict, raw):
    """Validate and convert a submitted value, or raise ValueError."""
    t = spec["type"]
    if t == "bool":
        if isinstance(raw, bool):
            return raw
        s = str(raw).strip().lower()
        if s not in ("true", "false"):
            raise ValueError("expected true or false")
        return s == "true"
    if t in ("int", "float"):
        try:
            val = int(raw) if t == "int" else float(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"expected {'an integer' if t == 'int' else 'a number'}") from exc
        lo, hi = spec.get("min"), spec.get("max")
        if lo is not None and val < lo:
            raise ValueError(f"must be >= {lo}")
        if hi is not None and val > hi:
            raise ValueError(f"must be <= {hi}")
        return val
    val = str(raw).strip()
    choices = spec.get("choices")
    if choices and val not in choices:
        raise ValueError(f"must be one of {', '.join(choices)}")
    if "\n" in val or "\r" in val:
        raise ValueError("must be a single line")
    return val


def _config_env_str(val) -> str:
    if isinstance(val, bool):
        return "true" if val else "false"
    return str(val)


def _config_view(authenticated: bool) -> dict:
    """Everything the console renders. Secret values are never included."""
    sections: dict[str, list] = {s: [] for s in CONFIG_SECTIONS}
    for spec in CONFIG_SPECS:
        value = _config_current_value(spec)
        secret = bool(spec.get("secret"))
        sections[spec["section"]].append(
            {
                "key": spec["key"],
                "type": spec["type"],
                "scope": spec["scope"],
                "desc": spec["desc"],
                "secret": secret,
                # Presence, never the value — this response is a redaction
                # boundary, so the secret must not travel even to an admin.
                "value": ("set" if str(value) else "") if secret else _config_env_str(value),
                "from_env": spec["key"] in os.environ,
                "choices": spec.get("choices"),
                "min": spec.get("min"),
                "max": spec.get("max"),
            }
        )
    return {
        "sections": [{"name": s, "settings": sections[s]} for s in CONFIG_SECTIONS],
        "authenticated": authenticated,
        "auth_configured": bool(settings.ADMIN_TOKEN),
        "editable": authenticated,
        "env_path": ENV_PATH,
        "pricing": [{"model": k, **v} for k, v in sorted(PRICING.items())],
        "pricing_editable": False,
    }


def _config_apply(changes: dict) -> dict:
    """Validate, persist and (where safe) hot-apply a batch of changes."""
    applied, rejected, restart_required = {}, {}, []
    for key, raw in changes.items():
        spec = CONFIG_INDEX.get(key)
        if spec is None:
            rejected[key] = "unknown setting"
            continue
        if spec["scope"] == "locked":
            rejected[key] = "locked — edit .env on the host and restart"
            continue
        try:
            val = _config_coerce(spec, raw)
        except ValueError as e:
            rejected[key] = str(e)
            continue
        env_val = _config_env_str(val)
        save_to_env(key, env_val)
        os.environ[key] = env_val
        var = spec.get("var")
        if spec["scope"] == "live" and var:
            setattr(settings, var, val)
        else:
            restart_required.append(key)
        applied[key] = env_val

    # Jitter bounds are a pair; a min above max would make randint raise on
    # every request, so normalise rather than let it blow up mid-traffic.
    if settings.TIMING_JITTER_MIN_MS > settings.TIMING_JITTER_MAX_MS:
        settings.TIMING_JITTER_MIN_MS = settings.TIMING_JITTER_MAX_MS
        save_to_env("TIMING_JITTER_MIN_MS", str(settings.TIMING_JITTER_MAX_MS))
        applied["TIMING_JITTER_MIN_MS"] = str(settings.TIMING_JITTER_MAX_MS)

    if applied:
        log(
            f"  {BG_GREEN}{BOLD} CONFIG {RESET} {GREEN}updated: {', '.join(sorted(applied))}{RESET}"
        )
    return {
        "applied": applied,
        "rejected": rejected,
        "restart_required": sorted(set(restart_required)),
    }
