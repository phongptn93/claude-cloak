"""Device-fingerprint capture, staleness, and derived IDs."""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime

from fastapi import Request

from . import settings, state
from .constants import CAPTURE_HEADERS, KNOWN_HEADERS
from .env import env_key, save_to_env
from .loki import _loki_enqueue
from .terminal import (
    BG_GREEN,
    BG_YELLOW,
    BOLD,
    DIM,
    GREEN,
    MAGENTA,
    RESET,
    WHITE,
    YELLOW,
    log,
    mask_value,
)


def generate_consistent_id(seed: str) -> str:
    """Generate a consistent ID using HMAC so all devices produce the same value."""
    return hmac.new(
        settings.SESSION_SECRET.encode(),
        seed.encode(),
        hashlib.sha256,
    ).hexdigest()[:32]


def _identity_age_days() -> float | None:
    """Return days since CAPTURED_AT, or None if no timestamp recorded."""
    if not state.runtime.captured_at:
        return None
    try:
        captured_dt = datetime.fromisoformat(state.runtime.captured_at)
    except (ValueError, TypeError):
        return None
    return (datetime.now() - captured_dt).total_seconds() / 86400.0


def is_identity_stale() -> bool:
    """True when captured fingerprint has aged past IDENTITY_REFRESH_DAYS."""
    if settings.IDENTITY_REFRESH_DAYS <= 0:
        return False
    age = _identity_age_days()
    if age is None:
        return False
    return age >= settings.IDENTITY_REFRESH_DAYS


def capture_identity_from_request(request: Request, path: str = "") -> None:

    # Gate every capture (initial OR refresh) on the same two checks so a
    # /dashboard or HEAD / can't ever set or re-set the fingerprint.
    if not path.lstrip("/").startswith("v1/messages"):
        return
    user_agent = request.headers.get("user-agent", "").lower()
    if not user_agent.startswith("claude-cli"):
        return

    # Already captured and still fresh — nothing to do.
    if state.runtime.identity_captured and not is_identity_stale():
        return

    # CAPTURE_LOCK_FROM_IP narrows the (re-)capturer to one specific IP. We
    # MUST check this BEFORE clearing the existing identity, otherwise a
    # stray request from a non-locked IP arriving past the refresh threshold
    # would wipe the fingerprint and then fail the IP gate, leaving the pool
    # un-locked.
    if settings.CAPTURE_LOCK_FROM_IP:
        client_ip = (request.client.host if request.client else "") or ""
        if client_ip != settings.CAPTURE_LOCK_FROM_IP:
            return

    if state.runtime.identity_captured and is_identity_stale():
        age = _identity_age_days()
        log("")
        log(
            f"  {BG_YELLOW}{BOLD} IDENTITY REFRESH {RESET} "
            f"{YELLOW}captured {age:.1f}d ago (≥ {settings.IDENTITY_REFRESH_DAYS}d threshold) "
            f"— clearing and re-capturing from this request{RESET}"
        )
        state.captured_identity.clear()
        state.runtime.identity_captured = False
        # Fall through to the capture block below.

    req_headers = {k.lower(): v for k, v in request.headers.items()}

    for h in CAPTURE_HEADERS:
        val = req_headers.get(h, "")
        if val:
            state.captured_identity[h] = val
            save_to_env(env_key(h), val)

    if state.captured_identity:
        state.runtime.identity_captured = True

        # Stamp capture time so the age-based refresh has a reference point.
        now_iso = datetime.now().isoformat(timespec="seconds")
        save_to_env("CAPTURED_AT", now_iso)
        state.runtime.captured_at = now_iso

        # Save session secret for consistent ID generation across devices
        save_to_env("SESSION_SECRET", settings.SESSION_SECRET)

        if settings.LOKI_ENABLED:
            _loki_enqueue(
                "identity",
                {
                    "headers_count": len(state.captured_identity),
                    "headers": sorted(state.captured_identity.keys()),
                },
            )

        log("")
        log(f"  {BG_GREEN}{BOLD} IDENTITY CAPTURED {RESET}")
        log(f"  {GREEN}Da bat {len(state.captured_identity)} headers tu Claude Code:{RESET}")
        for h, v in state.captured_identity.items():
            display = mask_value(v, 40) if len(v) > 50 else v
            log(f"    {MAGENTA}{h}{RESET}: {WHITE}{display}{RESET}")
        if settings.IDENTITY_REFRESH_DAYS > 0:
            log(
                f"  {DIM}auto-refresh in {settings.IDENTITY_REFRESH_DAYS} days "
                f"(set IDENTITY_REFRESH_DAYS=0 to disable){RESET}"
            )
        log(f"  {YELLOW}Da luu vao .env - Copy sang cac may khac!{RESET}")
        log("")


def warn_unknown_headers(request: Request):
    """Cảnh báo khi gặp header lạ chưa có trong danh sách đã biết."""

    req_headers = {k.lower() for k in request.headers}
    new_unknown = req_headers - KNOWN_HEADERS - state.warned_unknown_headers

    for h in sorted(new_unknown):
        state.warned_unknown_headers.add(h)
        log(
            f"  {BG_YELLOW}{BOLD} HEADER LA {RESET} {YELLOW}{BOLD}{h}{RESET}{YELLOW}: {request.headers.get(h, '')}{RESET}"
        )
        log(
            f"  {YELLOW}Header nay chua co trong CAPTURE_HEADERS, kiem tra xem co can lock khong!{RESET}"
        )
        log("")
