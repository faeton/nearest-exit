import asyncio

import pytest

from nearest_exit.probes.socks5 import socks5_probe


@pytest.fixture
async def socks5_port():
    async def handle(reader, writer):
        try:
            data = await reader.readexactly(3)
            if data == b"\x05\x01\x00":
                writer.write(b"\x05\x00")
                await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(handle, host="127.0.0.1", port=0)
    port = server.sockets[0].getsockname()[1]
    try:
        yield port
    finally:
        server.close()
        await server.wait_closed()


async def test_socks5_probe_success(socks5_port):
    res = await socks5_probe("local", "127.0.0.1", port=socks5_port, count=3, timeout_s=1.0)
    assert res.success
    assert res.rtt_ms is not None and res.rtt_ms < 100
    assert res.loss == 0.0
    assert res.probe == f"socks5/{socks5_port}"


async def test_socks5_probe_refused():
    res = await socks5_probe("dead", "127.0.0.1", port=1, count=2, timeout_s=0.5)
    assert not res.success
    assert res.loss == 1.0
    assert res.error
