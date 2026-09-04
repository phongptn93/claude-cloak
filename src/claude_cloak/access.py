"""IP whitelist, user-label resolution, and quota period helpers."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime

from . import settings


def is_ip_allowed(ip: str) -> bool:
    """Return True when ip falls inside any configured CIDR in ALLOWED_NETWORKS."""
    if not settings.ALLOWED_NETWORKS:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in settings.ALLOWED_NETWORKS)


def is_trusted_proxy(ip: str) -> bool:
    if not settings.TRUSTED_PROXY_NETWORKS:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in settings.TRUSTED_PROXY_NETWORKS)


def resolve_client_ip(peer_ip: str, forwarded_for: str) -> str:
    """The address every IP gate should judge.

    Normally the TCP peer. When the peer is a configured reverse proxy, the
    rightmost X-Forwarded-For entry that is not itself a trusted proxy — that
    is the address the trusted hop observed, and the last one a client cannot
    forge by prepending entries of its own.
    """
    if not forwarded_for or not is_trusted_proxy(peer_ip):
        return peer_ip
    for candidate in reversed([h.strip() for h in forwarded_for.split(",") if h.strip()]):
        if is_trusted_proxy(candidate):
            continue
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            return peer_ip
        return candidate
    return peer_ip


def label_for_ip(ip: str) -> str:
    """Return the human label for a source IP, falling back to the IP string."""
    if not ip:
        return "unknown"
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    return settings.IP_LABEL_MAP.get(addr, ip)


def cap_for_label(label: str) -> float:
    """Resolve the spend cap (USD) for a given user label."""
    return settings.USER_QUOTA_CAPS.get(label, settings.USER_QUOTA_DEFAULT_USD)


# Allowed character set for URL-prefix user labels. Restricted so labels can't
# inject path traversal, query strings, or other surprises into the upstream URL.
settings.USER_LABEL_RE = re.compile(r"^[A-Za-z0-9_\-.]{1,32}$")


def parse_user_prefix(path: str) -> tuple[str | None, str]:
    """Strip a leading `/u/<label>/...` from path.

    Returns (label, remaining_path). If no prefix is present or the label
    contains forbidden chars, returns (None, original_path).

    Client config example:
        ANTHROPIC_BASE_URL=http://vm:9999/u/phong
    Claude Code then sends /u/phong/v1/messages, which we account to
    user 'phong' and forward as /v1/messages.
    """
    stripped = path.lstrip("/")
    parts = stripped.split("/", 2)
    if len(parts) >= 2 and parts[0] == "u" and parts[1]:
        candidate = parts[1]
        if settings.USER_LABEL_RE.match(candidate):
            rest = parts[2] if len(parts) > 2 else ""
            return candidate, "/" + rest
    return None, path


def current_user_period_key() -> str:
    """Period key used to detect roll-over: 'YYYY-MM' or 'YYYY-MM-DD'."""
    if settings.USER_QUOTA_PERIOD == "daily":
        return datetime.now().strftime("%Y-%m-%d")
    return datetime.now().strftime("%Y-%m")


def seconds_until_user_period_reset() -> int:
    """Approx seconds until the current daily/monthly cap resets — for Retry-After."""
    now = datetime.now()
    if settings.USER_QUOTA_PERIOD == "daily":
        tomorrow = now.replace(hour=0, minute=0, second=0, microsecond=0)
        from datetime import timedelta

        target = tomorrow + timedelta(days=1)
    else:
        # First of next month at 00:00 local.
        year = now.year + (1 if now.month == 12 else 0)
        month = 1 if now.month == 12 else now.month + 1
        target = now.replace(
            year=year, month=month, day=1, hour=0, minute=0, second=0, microsecond=0
        )
    return max(1, int((target - now).total_seconds()))
