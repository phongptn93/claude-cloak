"""Console entry point: boot guards, then uvicorn."""

from __future__ import annotations

import asyncio
import sys

import uvicorn

from . import eventloop, settings, state
from .acme import acme_app
from .app import app
from .proxy_keys import active_key_count, load_keys
from .terminal import BG_RED, BOLD, CYAN, DIM, RED, RESET, YELLOW, enable_windows_ansi


def _abort_without_whitelist() -> None:
    """Server mode exposes the upstream billing surface — refuse an empty whitelist."""
    print()
    print(f"  {BG_RED}{BOLD} BOOT ABORTED {RESET}")
    print(
        f"  {RED}DEPLOY_MODE=server but ALLOWED_IPS is empty and no proxy key can let anyone in.{RESET}\n"
        f"  {YELLOW}Set ALLOWED_IPS in .env, e.g.:{RESET}\n"
        f"    {CYAN}ALLOWED_IPS=203.0.113.5,198.51.100.0/24{RESET}\n"
        f"  {YELLOW}Or run key-only: set PROXY_KEYS_ENABLED=true, then issue a key at "
        f"/keys from an ADMIN_IPS address.{RESET}\n"
        f"  {YELLOW}Refusing to bind {settings.LOCAL_HOST}:{settings.LOCAL_PORT} with no way to admit a client.{RESET}"
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
        # An empty whitelist is only survivable when something else can admit
        # a client. Proxy keys are that something — but only keys that exist
        # and still work, so load the store before deciding.
        load_keys()
        keyed = settings.PROXY_KEYS_ENABLED and active_key_count()
        if not keyed:
            _abort_without_whitelist()
        print(
            f"  {YELLOW}server mode with no ALLOWED_IPS: access is by proxy key only "
            f"({active_key_count()} active).{RESET}"
        )

    if settings.DEPLOY_MODE == "server" and not state.runtime.identity_captured:
        _warn_identity_unlocked()

    if settings.TLS_ENABLED:
        print(f"  {CYAN}TLS{RESET} terminating in-process with {settings.TLS_CERTFILE}")
    elif settings.DEPLOY_MODE == "server":
        print(
            f"  {YELLOW}No TLS: /v1 traffic — including each client's Authorization "
            f"header — crosses the network in cleartext.{RESET}\n"
            f"  {DIM}Set TLS_CERTFILE/TLS_KEYFILE, or front the proxy with a TLS "
            f"terminator listed in TRUSTED_PROXY_IPS.{RESET}"
        )

    main_config = uvicorn.Config(
        app,
        host=settings.LOCAL_HOST,
        port=settings.LOCAL_PORT,
        log_level="warning",
        # Don't expose server header
        server_header=False,
        date_header=False,
        ssl_certfile=settings.TLS_CERTFILE or None,
        ssl_keyfile=settings.TLS_KEYFILE or None,
    )

    if settings.HTTP_REDIRECT_PORT <= 0:
        # Server.run() would pick the event loop for us — on Windows that is
        # the proactor, where one vanished client closes the listener. Drive
        # serve() under our own loop instead (see eventloop.py).
        eventloop.run(uvicorn.Server(main_config).serve())
        return

    side_config = uvicorn.Config(
        acme_app,
        host=settings.LOCAL_HOST,
        port=settings.HTTP_REDIRECT_PORT,
        log_level="warning",
        server_header=False,
        date_header=False,
    )
    print(
        f"  {CYAN}HTTP{RESET} :{settings.HTTP_REDIRECT_PORT} -> redirect to HTTPS"
        + (f", ACME webroot {settings.ACME_WEBROOT}" if settings.ACME_WEBROOT else "")
    )

    async def serve_both() -> None:
        # Both listeners share one event loop, so the proxy's single-process
        # state model is untouched.
        await asyncio.gather(
            uvicorn.Server(main_config).serve(),
            uvicorn.Server(side_config).serve(),
        )

    eventloop.run(serve_both())


if __name__ == "__main__":
    main()
