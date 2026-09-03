"""Catch-all upstream proxy route."""

from __future__ import annotations

import asyncio
import contextlib
import random
import time
from datetime import datetime

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from .. import settings, state
from ..coach import _coach_record_request, _coach_record_response
from ..echo import echo_delay, echo_response, echo_sse_events, is_streaming_request
from ..identity import capture_identity_from_request, warn_unknown_headers
from ..loki import _loki_enqueue
from ..quota.tap import UsageTap
from ..quota.usage import _record_rate_limits, _record_usage
from ..sanitize import is_blocked_path, sanitize_body
from ..terminal import (
    BG_GREEN,
    BG_RED,
    BG_YELLOW,
    BLUE,
    BOLD,
    CYAN,
    DIM,
    MAGENTA,
    RED,
    RESET,
    YELLOW,
    log,
    mask_value,
)
from ..tokens import (
    _looks_like_cache_ttl_beta_error,
    disable_cache_ttl_runtime,
    inject_cache_ttl_beta,
    optimize_tokens,
)
from ..upstream import build_request_headers, filter_response_headers

router = APIRouter()


@router.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"])
async def proxy(path: str, request: Request):
    state.runtime.request_count += 1
    req_id = state.runtime.request_count

    now = datetime.now().strftime("%H:%M:%S")

    # Honour URL user-prefix (/u/<label>/<real-path>): drop the prefix so the
    # rest of this function works on the real upstream path. The middleware
    # already stored the parsed label in request.state.user_label.
    stripped = getattr(request.state, "stripped_path", None)
    if stripped is not None and stripped != "/" + path:
        path = stripped.lstrip("/")

    # ── Telemetry blocking ──
    if is_blocked_path(path):
        state.runtime.blocked_requests_count += 1
        log(
            f"  {DIM}{now}{RESET}  {CYAN}{BOLD}#{req_id}{RESET}  {BG_RED}{BOLD} BLOCKED {RESET} {RED}Telemetry: /{path}{RESET}"
        )
        log("")
        if settings.LOKI_ENABLED:
            _loki_enqueue("blocked", {"path": "/" + path, "method": request.method})
        return JSONResponse(
            status_code=200,
            content={"status": "ok"},
        )

    # Auto-capture identity headers, cảnh báo header lạ
    capture_identity_from_request(request, path)
    warn_unknown_headers(request)

    # ── Request timing jitter ──
    if settings.TIMING_JITTER_ENABLED:
        jitter_ms = random.randint(settings.TIMING_JITTER_MIN_MS, settings.TIMING_JITTER_MAX_MS)
        await _async_sleep(jitter_ms / 1000.0)

    target_url = f"{settings.ANTHROPIC_BASE_URL}/{path}"
    headers = build_request_headers(request)
    body = await request.body()

    # ── Body sanitization ──
    content_type = request.headers.get("content-type", "")
    body = sanitize_body(body, content_type)

    # ── Coaching: tool-result signals (counts only, never content) ──
    if settings.COACH_ENABLED:
        with contextlib.suppress(Exception):
            _coach_record_request(body, content_type, path)

    # ── Token saver ──
    if settings.TOKEN_SAVER_ENABLED:
        body = optimize_tokens(body, content_type, path)
        inject_cache_ttl_beta(headers)

    start_time = time.monotonic()

    # Request log
    log(
        f"  {DIM}{now}{RESET}  {CYAN}{BOLD}#{req_id}{RESET}  {BLUE}{BOLD}{request.method}{RESET} /{path}"
    )

    # Headers log (minimal - don't leak info in logs)
    sensitive = {"authorization", "x-api-key", "cookie"}
    spoofed = set(state.captured_identity.keys())
    for k, v in headers.items():
        kl = k.lower()
        if kl in sensitive:
            log(f"           {DIM}{k}: {RESET}{YELLOW}[REDACTED]{RESET}")
        elif kl in spoofed:
            log(
                f"           {DIM}{k}: {RESET}{MAGENTA}{mask_value(v, 20)}{RESET} {DIM}(locked){RESET}"
            )
        else:
            log(f"           {DIM}{k}: {mask_value(v, 30)}{RESET}")

    # ── Dev echo mode: answer locally, never touch the network ──
    if settings.DEV_ECHO_MODE:
        await echo_delay()
        usage_tap = UsageTap(
            "text/event-stream" if is_streaming_request(body) else "application/json",
            path,
            session_id=request.headers.get("x-claude-code-session-id"),
            user_label=getattr(request.state, "user_label", None),
        )
        elapsed = time.monotonic() - start_time
        log(
            f"  {DIM}{now}{RESET}  {CYAN}{BOLD}#{req_id}{RESET}  "
            f"{BG_YELLOW}{BOLD} ECHO {RESET} {DIM}{elapsed:.1f}s (DEV_ECHO_MODE, not forwarded){RESET}"
        )
        log("")

        def _finish() -> None:
            model, usage = usage_tap.finalize()
            if usage:
                _record_usage(
                    model,
                    usage,
                    usage_tap.session_id,
                    duration_ms=int((time.monotonic() - start_time) * 1000),
                    user_label=usage_tap.user_label,
                )
            if settings.COACH_ENABLED and usage_tap.is_messages:
                with contextlib.suppress(Exception):
                    _coach_record_response(*usage_tap.coach_signals())

        if is_streaming_request(body):
            frames = echo_sse_events(request.method, path, headers, body)

            async def echo_stream():
                try:
                    for frame in frames:
                        usage_tap.feed(frame)
                        yield frame
                finally:
                    _finish()

            return StreamingResponse(echo_stream(), status_code=200, media_type="text/event-stream")

        payload, content_type = echo_response(request.method, path, headers, body)
        usage_tap.feed(payload)
        _finish()
        return Response(content=payload, status_code=200, media_type=content_type)

    try:
        # Send with a bounded retry. This is safe only because no byte of the
        # response has reached the client yet — a transport failure here means
        # the request never produced output, so replaying it cannot duplicate
        # anything. Retrying costs one extra upstream call and saves the
        # client from surfacing a dead pooled connection as a stalled stream.
        send_started = time.monotonic()
        attempt = 0
        http_client = state.runtime.http_client
        if http_client is None:  # lifespan never ran
            raise RuntimeError("upstream client is not initialised")
        while True:
            req = http_client.build_request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=body,
                params=dict(request.query_params),
            )
            try:
                response = await http_client.send(req, stream=True)
                break
            except (httpx.ConnectError, httpx.ReadError, httpx.RemoteProtocolError) as e:
                attempt += 1
                if attempt > settings.UPSTREAM_CONNECT_RETRIES:
                    raise
                state.stream_stats["connect_retries"] += 1
                log(
                    f"           {YELLOW}upstream {type(e).__name__} — retry "
                    f"{attempt}/{settings.UPSTREAM_CONNECT_RETRIES}{RESET}"
                )
                await _async_sleep(settings.UPSTREAM_RETRY_BACKOFF_SECONDS * attempt)

        # A long gap before response headers usually means the request queued
        # for a free upstream connection — the classic silent-stall source.
        connect_ms = int((time.monotonic() - send_started) * 1000)
        if connect_ms >= settings.UPSTREAM_POOL_WAIT_WARN_MS:
            state.stream_stats["pool_waits"] += 1
            state.stream_stats["pool_wait_ms_total"] += connect_ms

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
            user_label=getattr(request.state, "user_label", None),
        )

        # Buffer 400 bodies so we can detect Anthropic beta-header rejection
        # and latch the cache-ttl beta off for subsequent requests.
        buffered_body: bytes | None = None
        if (
            status == 400
            and settings.TOKEN_SAVER_ENABLED
            and settings.CACHE_EXTEND_TTL
            and not state.runtime.cache_ttl_runtime_disabled
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
            retry_after = state.quota_stats["rate_limits"].get("retry-after")
            if retry_after:
                log(f"           {YELLOW}Rate limited - retry-after: {retry_after}s{RESET}")
            else:
                log(f"           {YELLOW}Qua nhieu request - doi mot chut...{RESET}")
        elif 400 <= status < 500:
            status_str = f"{BG_YELLOW}{BOLD} {status} {RESET}"
        else:
            status_str = f"{BG_RED}{BOLD} {status} {RESET}"

        log(
            f"  {DIM}{now}{RESET}  {CYAN}{BOLD}#{req_id}{RESET}  {status_str} {DIM}{elapsed:.1f}s{RESET}"
        )
        log("")

        if settings.LOKI_ENABLED and status >= 400:
            if status == 401:
                err_type = "unauthorized"
            elif status == 429:
                err_type = "rate_limit"
            elif status < 500:
                err_type = "client_error"
            else:
                err_type = "server_error"
            _loki_enqueue(
                "error",
                {
                    "status": status,
                    "path": "/" + path,
                    "method": request.method,
                    "duration_ms": int(elapsed * 1000),
                    "error_type": err_type,
                    "retry_after": state.quota_stats["rate_limits"].get("retry-after"),
                    "conversation_id": client_session_id or "",
                },
            )

        response_headers = filter_response_headers(response)

        # Strip Set-Cookie from responses to prevent cookie-based tracking
        response_headers = {k: v for k, v in response_headers.items() if k.lower() != "set-cookie"}

        if buffered_body is not None:
            # Even on 400 we still try to extract usage if present (rare but
            # harmless), so the tap sees the body too.
            usage_tap.feed(buffered_body)
            model, usage = usage_tap.finalize()
            total_ms = int((time.monotonic() - start_time) * 1000)
            if usage:
                _record_usage(
                    model,
                    usage,
                    usage_tap.session_id,
                    duration_ms=total_ms,
                    user_label=usage_tap.user_label,
                )
            if settings.COACH_ENABLED and usage_tap.is_messages:
                with contextlib.suppress(Exception):
                    _coach_record_response(*usage_tap.coach_signals())
            return Response(
                content=buffered_body,
                status_code=response.status_code,
                headers=response_headers,
                media_type=response.headers.get("content-type"),
            )

        is_sse = "event-stream" in (response.headers.get("content-type") or "").lower()

        async def stream_response():
            # Each cleanup step is guarded so a benign client disconnect or
            # a hiccup in the usage tap doesn't escape as an unhandled
            # exception (Starlette/uvicorn then surface it as an "ASGI
            # application" error even though the response was fully sent).
            state.stream_stats["streams_started"] += 1
            first_byte_at = None
            chunks = response.aiter_bytes().__aiter__()
            try:
                while True:
                    try:
                        if settings.UPSTREAM_STALL_SECONDS > 0:
                            chunk = await asyncio.wait_for(
                                chunks.__anext__(), settings.UPSTREAM_STALL_SECONDS
                            )
                        else:
                            chunk = await chunks.__anext__()
                    except StopAsyncIteration:
                        state.stream_stats["streams_completed"] += 1
                        break
                    except (TimeoutError, httpx.ReadTimeout):
                        # Upstream went silent. Anthropic pings during long
                        # thinking, so this is a dead connection, not a slow
                        # one. Close it out with a real error instead of
                        # leaving the client waiting on a stream that will
                        # never produce another byte.
                        state.stream_stats["stalls"] += 1
                        state.stream_stats["last_stall_at"] = datetime.now().isoformat(
                            timespec="seconds"
                        )
                        log(
                            f"  {BG_RED}{BOLD} STALL {RESET} {RED}#{req_id} upstream sent "
                            f"nothing for {settings.UPSTREAM_STALL_SECONDS:.0f}s — closing stream{RESET}"
                        )
                        if settings.LOKI_ENABLED:
                            _loki_enqueue(
                                "error",
                                {
                                    "status": 504,
                                    "path": "/" + path,
                                    "method": request.method,
                                    "duration_ms": int((time.monotonic() - start_time) * 1000),
                                    "error_type": "upstream_stall",
                                    "conversation_id": client_session_id or "",
                                },
                            )
                        if is_sse:
                            # Well-formed SSE error so the client reports a
                            # failed request it can retry, rather than a
                            # truncated success.
                            yield (
                                b'event: error\ndata: {"type":"error","error":'
                                b'{"type":"api_error","message":"claude-cloak: upstream '
                                b'stalled, no data received"}}\n\n'
                            )
                        break
                    if first_byte_at is None:
                        first_byte_at = time.monotonic()
                        ttfb_ms = int((first_byte_at - start_time) * 1000)
                        state.stream_stats["ttfb_ms_total"] += ttfb_ms
                        state.stream_stats["ttfb_samples"] += 1
                        if ttfb_ms > state.stream_stats["ttfb_ms_max"]:
                            state.stream_stats["ttfb_ms_max"] = ttfb_ms
                    usage_tap.feed(chunk)
                    yield chunk
            except (asyncio.CancelledError, GeneratorExit):
                # Client hung up mid-stream (closed tab, Ctrl-C, harness
                # cancelled the request). Benign — record and re-raise so the
                # server can finish tearing the response down.
                state.stream_stats["client_disconnects"] += 1
                raise
            finally:
                with contextlib.suppress(Exception):
                    await response.aclose()
                try:
                    total_ms = int((time.monotonic() - start_time) * 1000)
                    model, usage = usage_tap.finalize()
                    if usage:
                        _record_usage(
                            model,
                            usage,
                            usage_tap.session_id,
                            duration_ms=total_ms,
                            user_label=usage_tap.user_label,
                        )
                    if settings.COACH_ENABLED and usage_tap.is_messages:
                        _coach_record_response(*usage_tap.coach_signals())
                except Exception as e:
                    log(f"  {YELLOW}usage tap cleanup failed (non-fatal): {e}{RESET}")

        return StreamingResponse(
            stream_response(),
            status_code=response.status_code,
            headers=response_headers,
            media_type=response.headers.get("content-type"),
        )

    except httpx.TimeoutException:
        log(f"  {DIM}{now}{RESET}  {CYAN}{BOLD}#{req_id}{RESET}  {BG_RED}{BOLD} TIMEOUT {RESET}")
        log("")
        if settings.LOKI_ENABLED:
            _loki_enqueue(
                "error",
                {
                    "status": 504,
                    "path": "/" + path,
                    "method": request.method,
                    "duration_ms": int((time.monotonic() - start_time) * 1000),
                    "error_type": "timeout",
                },
            )
        raise HTTPException(status_code=504, detail="Gateway timeout") from None
    except httpx.ConnectError:
        log(
            f"  {DIM}{now}{RESET}  {CYAN}{BOLD}#{req_id}{RESET}  {BG_RED}{BOLD} CONNECT ERROR {RESET}"
        )
        log("")
        if settings.LOKI_ENABLED:
            _loki_enqueue(
                "error",
                {
                    "status": 502,
                    "path": "/" + path,
                    "method": request.method,
                    "duration_ms": int((time.monotonic() - start_time) * 1000),
                    "error_type": "connect_error",
                },
            )
        raise HTTPException(status_code=502, detail="Bad gateway") from None
    except Exception:
        # Don't leak internal error details
        log(f"  {DIM}{now}{RESET}  {CYAN}{BOLD}#{req_id}{RESET}  {BG_RED}{BOLD} ERROR {RESET}")
        log("")
        if settings.LOKI_ENABLED:
            _loki_enqueue(
                "error",
                {
                    "status": 500,
                    "path": "/" + path,
                    "method": request.method,
                    "duration_ms": int((time.monotonic() - start_time) * 1000),
                    "error_type": "proxy_error",
                },
            )
        raise HTTPException(status_code=500, detail="Internal proxy error") from None


async def _async_sleep(seconds: float):
    """Async sleep for timing jitter."""
    await asyncio.sleep(seconds)
