import asyncio

import pytest

from nearest_exit.probes.tcp import tcp_probe


@pytest.fixture
async def echo_port():
    server = await asyncio.start_server(
        lambda r, w: w.close(), host="127.0.0.1", port=0
    )
    port = server.sockets[0].getsockname()[1]
    try:
        yield port
    finally:
        server.close()
        await server.wait_closed()


async def test_tcp_probe_success(echo_port):
    res = await tcp_probe("local", "127.0.0.1", port=echo_port, count=3, timeout_s=1.0)
    assert res.success
    assert res.rtt_ms is not None and res.rtt_ms < 100
    assert res.loss == 0.0
    assert res.probe == f"tcp/{echo_port}"


async def test_tcp_probe_refused():
    # port 1 is reserved/closed on virtually every machine
    res = await tcp_probe("dead", "127.0.0.1", port=1, count=2, timeout_s=0.5)
    assert not res.success
    assert res.rtt_ms is None
    assert res.loss == 1.0
    assert res.error
