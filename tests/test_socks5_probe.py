import asyncio
import statistics

import pytest

from nearest_exit.probes.socks5 import _warm_samples, socks5_probe


def test_warm_samples_drops_first_attempt_when_it_succeeded():
    assert _warm_samples([10.0, 5.0, 6.0], True) == [5.0, 6.0]


def test_warm_samples_keeps_everything_when_first_attempt_was_lost():
    assert _warm_samples([None, 5.0, 6.0], True) == [5.0, 6.0]


def test_warm_samples_keeps_lone_success():
    assert _warm_samples([10.0, None, None], True) == [10.0]
    assert _warm_samples([None, None, 7.0], True) == [7.0]


def test_warm_samples_respects_discard_first_false():
    assert _warm_samples([10.0, 5.0], False) == [10.0, 5.0]


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


async def test_socks5_probe_keeps_warm_samples_when_first_attempt_fails(
    socks5_port, monkeypatch
):
    import nearest_exit.probes.socks5 as socks_mod

    calls = {"n": 0}
    real = socks_mod._one_handshake

    async def flaky(ip, port, timeout_s):
        calls["n"] += 1
        if calls["n"] == 1:
            return None
        return await real(ip, port, timeout_s)

    monkeypatch.setattr(socks_mod, "_one_handshake", flaky)
    res = await socks5_probe("local", "127.0.0.1", port=socks5_port,
                             count=3, timeout_s=1.0)
    assert res.success
    assert len(res.samples) == 2
    assert res.rtt_ms == pytest.approx(statistics.median(res.samples))
    assert res.loss == pytest.approx(1 / 3)


async def test_socks5_probe_refused():
    res = await socks5_probe("dead", "127.0.0.1", port=1, count=2, timeout_s=0.5)
    assert not res.success
    assert res.loss == 1.0
    assert res.error
