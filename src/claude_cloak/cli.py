"""Console entry point: boot guards, then uvicorn."""

from __future__ import annotations

import sys

import uvicorn

from . import settings, state
from .app import app
from .terminal import BG_RED, BOLD, CYAN, DIM, RED, RESET, YELLOW, enable_windows_ansi


def _abort_without_whitelist() -> None:
    """Server mode exposes the upstream billing surface — refuse an empty whitelist."""
    print()
    print(f"  {BG_RED}{BOLD} BOOT ABORTED {RESET}")
    print(
        f"  {RED}DEPLOY_MODE=server but ALLOWED_IPS is empty.{RESET}\n"
        f"  {YELLOW}Set ALLOWED_IPS in .env, e.g.:{RESET}\n"
        f"    {CYAN}ALLOWED_IPS=203.0.113.5,198.51.100.0/24{RESET}\n"
        f"  {YELLOW}Refusing to bind {settings.LOCAL_HOST}:{settings.LOCAL_PORT} with no whitelist.{RESET}"
    )
    print()
    sys.exit(1)


def _warn_identity_unlocked() -> None:
    print()
    if settings.CAPTURE_LOCK_FROM_IP:
        print(
            f"  {YELLOW}server mode: identity will be locked from the first "
            f"request whose source IP = {BOLD}{settings.CAPTURE_LOCK_FROM_IP}{RESET}{YELLOW}.{RESET}"
        )
    else:
        print(
            f"  {YELLOW}server mode: the next request from ANY whitelisted IP "
            f"will lock the device identity for the whole pool.{RESET}"
        )
        print(
            f"  {DIM}set CAPTURE_LOCK_FROM_IP=<ip> in .env if you want to restrict "
            f"who can be the first-capturer.{RESET}"
        )
    print()


def main() -> None:
    enable_windows_ansi()

    if settings.DEPLOY_MODE == "server" and not settings.ALLOWED_NETWORKS:
        _abort_without_whitelist()

    if settings.DEPLOY_MODE == "server" and not state.runtime.identity_captured:
        _warn_identity_unlocked()

    uvicorn.run(
        app,
        host=settings.LOCAL_HOST,
        port=settings.LOCAL_PORT,
        log_level="warning",
        # Don't expose server header
        server_header=False,
        date_header=False,
    )


if __name__ == "__main__":
    main()
