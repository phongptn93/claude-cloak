"""Listener resilience: a dying client must not take the service with it.

The bug this guards is specific and severe. On Windows, asyncio's proactor
loop closes the LISTENING socket when accept() fails — and a client that
vanishes mid-handshake (WinError 64), which any public port sees daily, is
such a failure. The proxy then stays up serving nothing. Everything here
exists to keep that from happening, and to keep the console readable while a
scanner hammers the port.
"""

from __future__ import annotations

import asyncio
import errno
import logging
import sys

import pytest

from claude_cloak import eventloop, settings, state


def _oserror(winerror: int | None = None, err: int | None = None) -> OSError:
    """Synthesize a Windows-shaped OSError on any platform.

    The 5-argument constructor only sets `winerror` on Windows, so the
    attribute is attached directly — what the code reads is the attribute.
    """
    exc = OSError(err or errno.EINVAL, "synthetic")
    if winerror is not None:
        # `winerror` is a Windows-only attribute of OSError, so on other
        # platforms it has to be attached rather than constructed.
        setattr(exc, "winerror", winerror)  # noqa: B010
    return exc


@pytest.mark.parametrize("winerror", sorted(eventloop.BENIGN_WINERRORS))
def test_every_windows_disconnect_code_is_benign(winerror):
    assert eventloop.is_benign_network_error(_oserror(winerror=winerror)) is True


def test_the_reported_winerror_64_is_benign():
    """The exact error from the field report: the peer went away."""
    assert eventloop.is_benign_network_error(_oserror(winerror=64)) is True


@pytest.mark.parametrize(
    "exc",
    [
        ConnectionResetError(),
        ConnectionAbortedError(),
        BrokenPipeError(),
        TimeoutError(),
        OSError(errno.ECONNRESET, "reset"),
    ],
)
def test_posix_disconnects_are_benign_too(exc):
    assert eventloop.is_benign_network_error(exc) is True


@pytest.mark.parametrize(
    "exc",
    [
        None,
        ValueError("a real bug"),
        OSError(errno.EACCES, "permission denied"),
        _oserror(winerror=5),
        MemoryError(),
    ],
)
def test_real_failures_are_not_swallowed(exc):
    assert eventloop.is_benign_network_error(exc) is False


def test_the_handler_counts_a_dropped_client_instead_of_raising(monkeypatch):
    monkeypatch.setattr(settings, "NETWORK_NOISE_WARN_INTERVAL", 0)
    loop = asyncio.new_event_loop()
    try:
        escaped = []
        monkeypatch.setattr(
            type(loop), "default_exception_handler", lambda self, ctx: escaped.append(ctx)
        )
        eventloop.exception_handler(loop, {"message": "Accept failed", "exception": _oserror(64)})
        assert escaped == []
        assert state.runtime.aborted_connections == 1
        assert state.runtime.last_listener_event == "WinError 64"
    finally:
        loop.close()


def test_the_handler_still_surfaces_a_real_error(monkeypatch):
    loop = asyncio.new_event_loop()
    try:
        escaped = []
        monkeypatch.setattr(
            type(loop), "default_exception_handler", lambda self, ctx: escaped.append(ctx)
        )
        eventloop.exception_handler(loop, {"message": "boom", "exception": ValueError("boom")})
        assert len(escaped) == 1
        assert state.runtime.aborted_connections == 0
    finally:
        loop.close()


def test_repeated_drops_are_summarised_not_repeated(monkeypatch):
    """A scanner produces thousands; the console must stay readable."""
    lines = []
    monkeypatch.setattr(eventloop, "log", lines.append)
    monkeypatch.setattr(settings, "NETWORK_NOISE_WARN_INTERVAL", 600)
    for _ in range(50):
        eventloop._report_dropped("WinError 64")
    assert state.runtime.aborted_connections == 50
    assert len(lines) == 1, "one summary line, not fifty tracebacks"
    assert "1 client connection(s) dropped" in lines[0]


def test_the_invalid_request_filter_explains_and_collapses(monkeypatch):
    monkeypatch.setattr(settings, "NETWORK_NOISE_WARN_INTERVAL", 600)
    monkeypatch.setattr(settings, "TLS_ENABLED", False)
    filt = eventloop.InvalidRequestFilter()

    def record():
        return logging.LogRecord(
            "uvicorn.error",
            logging.WARNING,
            __file__,
            0,
            eventloop.UVICORN_INVALID_REQUEST,
            (),
            None,
        )

    first = record()
    assert filt.filter(first) is True
    assert "https://" in first.getMessage(), "the operator is told the likely cause"
    assert str(settings.LOCAL_PORT) in first.getMessage()

    for _ in range(9):
        assert filt.filter(record()) is False
    assert state.runtime.invalid_http_requests == 10


def test_the_filter_leaves_other_uvicorn_warnings_alone():
    filt = eventloop.InvalidRequestFilter()
    other = logging.LogRecord(
        "uvicorn.error", logging.WARNING, __file__, 0, "disk on fire", (), None
    )
    assert filt.filter(other) is True
    assert other.getMessage() == "disk on fire"


def test_the_filter_is_installed_once():
    eventloop.install_http_noise_filter()
    eventloop.install_http_noise_filter()
    logger = logging.getLogger("uvicorn.error")
    installed = [f for f in logger.filters if isinstance(f, eventloop.InvalidRequestFilter)]
    assert len(installed) == 1
    logger.filters = [
        f for f in logger.filters if not isinstance(f, eventloop.InvalidRequestFilter)
    ]


def test_no_loop_is_forced_off_windows(monkeypatch):
    monkeypatch.setattr(eventloop.sys, "platform", "linux")
    assert eventloop.loop_factory() is None


def test_windows_serves_on_the_selector_loop(monkeypatch):
    """The whole point: the proactor's accept() failure closes the listener."""
    monkeypatch.setattr(eventloop.sys, "platform", "win32")
    monkeypatch.setattr(settings, "WINDOWS_EVENT_LOOP", "selector")
    assert eventloop.loop_factory() is asyncio.SelectorEventLoop


def test_windows_can_opt_back_into_the_proactor(monkeypatch):
    monkeypatch.setattr(eventloop.sys, "platform", "win32")
    monkeypatch.setattr(settings, "WINDOWS_EVENT_LOOP", "proactor")
    assert eventloop.loop_factory() is getattr(asyncio, "ProactorEventLoop", None)


def test_run_installs_both_guards_on_the_loop_it_creates():
    seen = {}

    async def main():
        loop = asyncio.get_running_loop()
        seen["handler"] = loop.get_exception_handler()

    eventloop.run(main())
    assert seen["handler"] is eventloop.exception_handler
    logger = logging.getLogger("uvicorn.error")
    assert any(isinstance(f, eventloop.InvalidRequestFilter) for f in logger.filters)
    logger.filters = [
        f for f in logger.filters if not isinstance(f, eventloop.InvalidRequestFilter)
    ]


@pytest.mark.skipif(sys.platform == "win32", reason="selector loop is the Windows default here")
def test_the_default_loop_is_untouched_on_this_platform():
    assert eventloop.loop_factory() is None
