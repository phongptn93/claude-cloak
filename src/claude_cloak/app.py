"""FastAPI application factory and process lifespan."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, suppress

import httpx
from fastapi import FastAPI

from . import settings, state
from .banner import print_banner, print_status
from .coach import _load_coach_stats, _save_coach_stats
from .env import ENV_PATH, save_to_env
from .loki import _loki_flush_once, _loki_flusher_loop
from .middleware import AccessControlMiddleware
from .quota.persist import _load_quota_stats, _save_quota_stats
from .routes import admin, coach, config, health, pages, passthrough, quota
from .terminal import RESET, YELLOW, log


def build_upstream_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=httpx.Timeout(
            settings.UPSTREAM_READ_TIMEOUT,
            connect=settings.UPSTREAM_CONNECT_TIMEOUT,
            pool=settings.UPSTREAM_POOL_TIMEOUT,
        ),
        limits=httpx.Limits(
            max_connections=settings.UPSTREAM_MAX_CONNECTIONS,
            max_keepalive_connections=settings.UPSTREAM_MAX_KEEPALIVE,
            keepalive_expiry=settings.UPSTREAM_KEEPALIVE_EXPIRY,
        ),
    )


def build_telemetry_client() -> httpx.AsyncClient:
    # Telemetry gets its own small pool. Sharing the upstream client would let
    # a slow Loki push occupy a connection slot that an API request needs.
    return httpx.AsyncClient(
        timeout=httpx.Timeout(
            settings.LOKI_TIMEOUT_SECONDS,
            connect=settings.TELEMETRY_CONNECT_TIMEOUT,
            pool=settings.TELEMETRY_POOL_TIMEOUT,
        ),
        limits=httpx.Limits(
            max_connections=settings.TELEMETRY_MAX_CONNECTIONS,
            max_keepalive_connections=settings.TELEMETRY_MAX_KEEPALIVE,
        ),
    )


def persist_generated_session_secret() -> None:
    """Write a freshly generated SESSION_SECRET to .env, once.

    Without this the secret is new on every start, so every /config sign-in
    dies on restart — and this service restarts on each certificate renewal.
    identity.py already saved it, but only inside identity capture, which
    server mode disables; a shared deployment therefore never reached it.
    """
    if not settings.SESSION_SECRET_GENERATED:
        return
    try:
        save_to_env("SESSION_SECRET", settings.SESSION_SECRET)
    except OSError as exc:
        log(
            f"  {YELLOW}SESSION_SECRET could not be saved to {ENV_PATH} ({exc}). "
            f"Admin sessions will not survive a restart.{RESET}"
        )
        return
    settings.SESSION_SECRET_GENERATED = False


@asynccontextmanager
async def lifespan(app: FastAPI):
    persist_generated_session_secret()
    state.runtime.http_client = build_upstream_client()
    state.runtime.telemetry_client = build_telemetry_client()
    _load_quota_stats()
    _load_coach_stats()
    print_banner()
    print_status()
    if settings.LOKI_ENABLED:
        state.runtime.loki_flusher_task = asyncio.create_task(_loki_flusher_loop())
    try:
        yield
    finally:
        task = state.runtime.loki_flusher_task
        if task is not None:
            task.cancel()
            with suppress(asyncio.CancelledError, Exception):
                await task
            # Best-effort final flush so in-flight events aren't lost.
            for _ in range(settings.LOKI_SHUTDOWN_FLUSHES):
                if not state.loki_buffer:
                    break
                if not await _loki_flush_once():
                    break
        _save_quota_stats(force=True)
        _save_coach_stats(force=True)
        if state.runtime.http_client is not None:
            await state.runtime.http_client.aclose()
        if state.runtime.telemetry_client is not None:
            await state.runtime.telemetry_client.aclose()


def create_app() -> FastAPI:
    application = FastAPI(title="Claude Cloak", lifespan=lifespan)
    application.add_middleware(AccessControlMiddleware)
    for module in (health, pages, config, coach, quota, admin):
        application.include_router(module.router)
    # Catch-all last: it matches every remaining path.
    application.include_router(passthrough.router)
    return application


app = create_app()
