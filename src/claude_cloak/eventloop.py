"""Event-loop choice, and the network noise a public listener attracts.

Two things go wrong on a port open to the internet. On Windows the first of
them is not noise at all — it silently ends the service:

1. **A client can vanish between the TCP handshake and accept().** Windows
   reports that as ``OSError [WinError 64] The specified network name is no
   longer available``. CPython's proactor loop — asyncio's default on Windows,
   and what uvicorn picks there — treats an accept error as fatal for the
   LISTENING socket::

       except OSError as exc:            # asyncio/proactor_events.py
           if sock.fileno() != -1:
               self.call_exception_handler({...})
               sock.close()              # <- the listener is gone

   The process stays up, already-open connections keep working, and no new
   client can ever connect again — a dead proxy that looks alive. The selector
   loop does not do this: it logs the failed accept and keeps serving. So on
   Windows we run on the selector loop unless the operator asks for the
   proactor back.

2. **Non-HTTP bytes** — a port scanner, or a client speaking TLS to a plain
   HTTP port — make h11 raise and uvicorn log a bare "Invalid HTTP request
   received." A scanner repeats that often enough to bury the request log,
   while the one thing an operator needs (what is causing it) is missing.

Both are handled here: the first by the loop choice plus an exception handler
that reports dropped connections as one compact, rate-limited line instead of
a multi-frame traceback; the second by a log filter that keeps the signal and
drops the repetition.
"""

from __future__ import annotations

import asyncio
import errno
import logging
import sys
import time
from collections.abc import Callable, Coroutine
from typing import Any

from . import settings, state
from .terminal import DIM, RESET, YELLOW, log

# Windows error codes for "the peer went away", none of which say anything
# about the health of this process.
#   64   ERROR_NETNAME_DELETED      121  ERROR_SEM_TIMEOUT
#   995  ERROR_OPERATION_ABORTED    1236 ERROR_CONNECTION_ABORTED
#   10053 WSAECONNABORTED           10054 WSAECONNRESET
BENIGN_WINERRORS = frozenset({64, 121, 995, 1236, 10053, 10054})

BENIGN_ERRNOS = frozenset(
    {
        errno.ECONNRESET,
        errno.ECONNABORTED,
        errno.EPIPE,
        errno.ETIMEDOUT,
        errno.ENOTCONN,
        errno.ESHUTDOWN,
    }
)

BENIGN_EXCEPTIONS = (
    ConnectionResetError,
    ConnectionAbortedError,
    BrokenPipeError,
    TimeoutError,
)

UVICORN_INVALID_REQUEST = "Invalid HTTP request received."


def is_benign_network_error(exc: BaseException | None) -> bool:
    """True for a failure that means 'the client left', not 'we are broken'."""
    if exc is None:
        return False
    if isinstance(exc, BENIGN_EXCEPTIONS):
        return True
    if isinstance(exc, OSError):
        if getattr(exc, "winerror", None) in BENIGN_WINERRORS:
            return True
        return exc.errno in BENIGN_ERRNOS
    return False


def _describe(exc: BaseException | None) -> str:
    winerror = getattr(exc, "winerror", None)
    if winerror:
        return f"WinError {winerror}"
    if isinstance(exc, OSError) and exc.errno:
        return errno.errorcode.get(exc.errno, f"errno {exc.errno}")
    return type(exc).__name__ if exc else "unknown"


def _plaintext_port_hint() -> str:
    """The likeliest cause, which depends on whether we terminate TLS."""
    if settings.TLS_ENABLED:
        return "a client using http:// against this HTTPS port, or a port scan"
    return "a client using https:// against this plain-HTTP port, or a port scan"


def _report_dropped(reason: str) -> None:
    """One line per NETWORK_NOISE_WARN_INTERVAL, carrying the count since the last."""
    state.runtime.aborted_connections += 1
    state.runtime.last_listener_event = reason
    now = time.monotonic()
    interval = settings.NETWORK_NOISE_WARN_INTERVAL
    # 0.0 means "never reported". Comparing against it directly would silence
    # the first report on a freshly booted machine, where monotonic() is still
    # smaller than the interval — which is exactly when the proxy starts.
    last = state.runtime.last_listener_warn_at
    if interval > 0 and last and now - last < interval:
        return
    since = state.runtime.aborted_connections - state.runtime.reported_aborted_connections
    state.runtime.last_listener_warn_at = now
    state.runtime.reported_aborted_connections = state.runtime.aborted_connections
    log(
        f"  {YELLOW}{since} client connection(s) dropped before a request arrived "
        f"(last: {reason}).{RESET} {DIM}Usually {_plaintext_port_hint()}. "
        f"The listener is unaffected.{RESET}"
    )


def exception_handler(loop: asyncio.AbstractEventLoop, context: dict) -> None:
    """Keep a dying client off the console, and everything else on it."""
    exc = context.get("exception")
    if is_benign_network_error(exc):
        _report_dropped(_describe(exc))
        return
    loop.default_exception_handler(context)


class InvalidRequestFilter(logging.Filter):
    """Collapse uvicorn's bare "Invalid HTTP request received." into a line
    that says what it probably is, at most once per warn interval."""

    def filter(self, record: logging.LogRecord) -> bool:
        if record.getMessage() != UVICORN_INVALID_REQUEST:
            return True
        state.runtime.invalid_http_requests += 1
        now = time.monotonic()
        interval = settings.NETWORK_NOISE_WARN_INTERVAL
        last = state.runtime.last_invalid_request_warn_at
        if interval > 0 and last and now - last < interval:
            return False
        since = state.runtime.invalid_http_requests - state.runtime.reported_invalid_requests
        state.runtime.last_invalid_request_warn_at = now
        state.runtime.reported_invalid_requests = state.runtime.invalid_http_requests
        record.msg = (
            f"{since} non-HTTP request(s) on port {settings.LOCAL_PORT} — "
            f"likely {_plaintext_port_hint()}. Each was answered with 400 and dropped."
        )
        record.args = ()
        return True


def install_http_noise_filter() -> None:
    """Attach the filter to the logger uvicorn reports protocol errors on."""
    logger = logging.getLogger("uvicorn.error")
    if not any(isinstance(f, InvalidRequestFilter) for f in logger.filters):
        logger.addFilter(InvalidRequestFilter())


def loop_factory() -> Callable[[], asyncio.AbstractEventLoop] | None:
    """The event loop to serve on. None = whatever asyncio would pick.

    Only Windows needs an opinion here, for the accept() reason above.
    """
    if sys.platform != "win32":
        return None
    if settings.WINDOWS_EVENT_LOOP == "proactor":
        return getattr(asyncio, "ProactorEventLoop", None)
    return getattr(asyncio, "SelectorEventLoop", None)


def run(main: Coroutine[Any, Any, Any]) -> None:
    """Run `main` on the right loop, with both noise handlers installed."""
    install_http_noise_filter()
    factory = loop_factory()
    with asyncio.Runner(loop_factory=factory) as runner:
        runner.get_loop().set_exception_handler(exception_handler)
        runner.run(main)
