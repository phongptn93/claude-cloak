"""Pool waits must count only the queue for a connection slot.

Anthropic takes seconds to send response headers on a large prompt. Timing the
whole send reported that latency as pool saturation, even on a pool far larger
than the traffic.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from claude_cloak import settings, state
from claude_cloak.upstream import SendTimer, _stream_health_view, record_send_timing

HEADER_DELAY = 0.3


@pytest.fixture
async def slow_server():
    """HTTP/1.1 server that waits HEADER_DELAY before sending headers."""

    async def handle(reader, writer):
        try:
            while True:
                head = await reader.readuntil(b"\r\n\r\n")
                if not head:
                    break
                await asyncio.sleep(HEADER_DELAY)
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}/"
    server.close()
    await server.wait_closed()


async def _timed_get(client: httpx.AsyncClient, url: str) -> SendTimer:
    timer = SendTimer()
    response = await client.get(url, extensions={"trace": timer})
    await response.aread()
    record_send_timing(timer)
    return timer


async def test_slow_upstream_headers_are_not_a_pool_wait(slow_server, monkeypatch):
    monkeypatch.setattr(settings, "UPSTREAM_POOL_WAIT_WARN_MS", 100)
    async with httpx.AsyncClient(limits=httpx.Limits(max_connections=10)) as client:
        first = await _timed_get(client, slow_server)
        second = await _timed_get(client, slow_server)

    assert first.pool_wait_ms < 100 and second.pool_wait_ms < 100
    assert first.connect_ms is not None  # opened a connection
    assert second.connect_ms is None  # reused it
    view = _stream_health_view()
    assert view["pool_waits"] == 0
    assert view["new_connections"] == 1


async def test_saturated_pool_is_still_reported(slow_server, monkeypatch):
    monkeypatch.setattr(settings, "UPSTREAM_POOL_WAIT_WARN_MS", 100)
    async with httpx.AsyncClient(limits=httpx.Limits(max_connections=1)) as client:
        timers = await asyncio.gather(*(_timed_get(client, slow_server) for _ in range(2)))

    waits = sorted(t.pool_wait_ms for t in timers)
    assert waits[0] < 100
    assert waits[1] >= HEADER_DELAY * 1000 * 0.8
    assert state.stream_stats["pool_waits"] == 1
