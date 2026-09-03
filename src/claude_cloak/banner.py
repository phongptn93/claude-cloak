"""Startup banner and configuration summary."""

from __future__ import annotations

import sys

from . import settings, state
from .constants import BLOCKED_PATH_PATTERNS, SANITIZE_BODY_FIELDS, STRIP_REQUEST_HEADERS
from .identity import _identity_age_days
from .terminal import BOLD, CYAN, DIM, GREEN, MAGENTA, RESET, WHITE, YELLOW, mask_value


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
    try:
        print(banner)
    except UnicodeEncodeError:
        enc = getattr(sys.stdout, "encoding", None) or "ascii"
        sys.stdout.write(banner.encode(enc, errors="replace").decode(enc) + "\n")


def print_status():
    if state.runtime.identity_captured:
        age = _identity_age_days()
        if settings.IDENTITY_REFRESH_DAYS > 0 and age is not None:
            refresh_in = max(0.0, settings.IDENTITY_REFRESH_DAYS - age)
            age_str = f"{DIM}(captured {age:.1f}d ago, refresh in {refresh_in:.1f}d){RESET}"
        elif settings.IDENTITY_REFRESH_DAYS > 0:
            age_str = f"{DIM}(no CAPTURED_AT — will stamp on next request){RESET}"
        else:
            age_str = f"{DIM}(auto-refresh disabled){RESET}"
        identity_status = f"{GREEN}{len(state.captured_identity)} headers locked{RESET} {age_str}"
    else:
        identity_status = f"{YELLOW}Waiting for first request...{RESET}"

    jitter_status = (
        f"{GREEN}ON ({settings.TIMING_JITTER_MIN_MS}-{settings.TIMING_JITTER_MAX_MS}ms){RESET}"
        if settings.TIMING_JITTER_ENABLED
        else f"{YELLOW}OFF{RESET}"
    )
    telemetry_status = f"{GREEN}{len(BLOCKED_PATH_PATTERNS)} patterns blocked{RESET}"

    if settings.DEPLOY_MODE == "server":
        mode_status = f"{GREEN}server{RESET} {DIM}(bind {settings.LOCAL_HOST}:{settings.LOCAL_PORT}, {len(settings.ALLOWED_NETWORKS)} CIDR whitelisted){RESET}"
    else:
        mode_status = (
            f"{YELLOW}local{RESET} {DIM}(127.0.0.1:{settings.LOCAL_PORT}, no whitelist){RESET}"
        )

    if settings.USER_QUOTA_ENABLED:
        uq_status = (
            f"{GREEN}ON{RESET} {DIM}({settings.USER_QUOTA_PERIOD}, default cap "
            f"${settings.USER_QUOTA_DEFAULT_USD:.2f}, hard={settings.USER_QUOTA_HARD_LIMIT}){RESET}"
        )
    else:
        uq_status = f"{YELLOW}OFF{RESET}"

    print(f"  {DIM}{'─' * 60}{RESET}")
    print(f"  {CYAN} Mode        {RESET}{mode_status}")
    print(
        f"  {CYAN} Server      {RESET}{WHITE}http://{'localhost' if settings.LOCAL_HOST in ('127.0.0.1', '0.0.0.0') else settings.LOCAL_HOST}:{settings.LOCAL_PORT}{RESET}"
    )
    print(f"  {CYAN} Target      {RESET}{WHITE}{settings.ANTHROPIC_BASE_URL}{RESET}")
    print(f"  {DIM}{'─' * 60}{RESET}")
    print(f"  {CYAN} Identity    {RESET}{identity_status}")
    print(f"  {CYAN} Telemetry   {RESET}{telemetry_status}")
    print(f"  {CYAN} Timing      {RESET}{jitter_status}")
    print(f"  {CYAN} Body Scrub  {RESET}{GREEN}{len(SANITIZE_BODY_FIELDS)} fields monitored{RESET}")
    print(
        f"  {CYAN} IP Strip    {RESET}{GREEN}{len(STRIP_REQUEST_HEADERS)} headers stripped{RESET}"
    )
    if settings.TOKEN_SAVER_ENABLED:
        ts_parts = []
        if settings.CACHE_EXTEND_TTL:
            ts_parts.append("cache 1h")
        if settings.TOOL_RESULT_TRUNCATE:
            ts_parts.append(f"tool-trunc>{settings.TOOL_RESULT_MAX_BYTES}b")
        ts_status = f"{GREEN}ON ({', '.join(ts_parts) or 'no-op'}){RESET}"
    else:
        ts_status = f"{YELLOW}OFF{RESET}"
    print(f"  {CYAN} Token Saver {RESET}{ts_status}")
    if settings.QUOTA_TRACKING_ENABLED:
        if state.quota_stats["messages_requests"]:
            cost = state.quota_stats["cost_usd_total"]
            reqs = state.quota_stats["messages_requests"]
            quota_status = (
                f"{GREEN}ON{RESET} {DIM}(loaded ${cost:.4f} / {reqs} reqs from .quota.json){RESET}"
            )
        else:
            quota_status = f"{GREEN}ON{RESET}"
    else:
        quota_status = f"{YELLOW}OFF{RESET}"
    print(f"  {CYAN} Quota Track {RESET}{quota_status}")
    print(f"  {CYAN} User Quota  {RESET}{uq_status}")
    if settings.QUOTA_TRACKING_ENABLED:
        print(
            f"  {CYAN} Dashboard   {RESET}{WHITE}http://localhost:{settings.LOCAL_PORT}/dashboard{RESET}"
        )
    if settings.LOKI_ENABLED:
        loki_status = f"{GREEN}ON{RESET} {DIM}({settings.LOKI_URL} · job={settings.LOKI_JOB} · host={settings.LOKI_HOST}){RESET}"
    else:
        loki_status = f"{YELLOW}OFF{RESET}"
    print(f"  {CYAN} Loki        {RESET}{loki_status}")
    if state.runtime.identity_captured:
        print(f"  {DIM}{'─' * 60}{RESET}")
        for h, v in state.captured_identity.items():
            display = mask_value(v, 40) if len(v) > 50 else v
            print(f"  {DIM}  {h}: {MAGENTA}{display}{RESET}")
    print(f"  {DIM}{'─' * 60}{RESET}")
    print()
