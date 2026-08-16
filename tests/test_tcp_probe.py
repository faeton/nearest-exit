import asyncio
import statistics

import pytest

from nearest_exit.probes.tcp import _warm_samples, tcp_probe


def test_warm_samples_drops_first_attempt_when_it_succeeded():
    assert _warm_samples([10.0, 5.0, 6.0], True) == [5.0, 6.0]


def test_warm_samples_keeps_everything_when_first_attempt_was_lost():
    # The cold packet is the one that never came back; the survivors are warm.
    assert _warm_samples([None, 5.0, 6.0], True) == [5.0, 6.0]


def test_warm_samples_keeps_lone_success_from_first_attempt():
    assert _warm_samples([10.0, None, None], True) == [10.0]


def test_warm_samples_keeps_lone_late_success():
    assert _warm_samples([None, None, 7.0], True) == [7.0]


def test_warm_samples_respects_discard_first_false():
    assert _warm_samples([10.0, 5.0], False) == [10.0, 5.0]


def test_warm_samples_empty():
    assert _warm_samples([None, None], True) == []
    assert _warm_samples([], True) == []


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


async def test_tcp_probe_reports_all_samples(echo_port):
    res = await tcp_probe("local", "127.0.0.1", port=echo_port, count=3, timeout_s=1.0)
    # samples keeps every success, including the discarded cold one.
    assert len(res.samples) == 3


async def test_tcp_probe_partial_loss(echo_port, monkeypatch):
    import nearest_exit.probes.tcp as tcp_mod

    calls = {"n": 0}
    real = tcp_mod._one_connect

    async def flaky(ip, port, timeout_s):
        calls["n"] += 1
        if calls["n"] == 1:  # first attempt lost
            return None
        return await real(ip, port, timeout_s)

    monkeypatch.setattr(tcp_mod, "_one_connect", flaky)
    res = await tcp_probe("local", "127.0.0.1", port=echo_port, count=3, timeout_s=1.0)
    assert res.success
    assert res.loss == pytest.approx(1 / 3)
    assert len(res.samples) == 2
    # Both warm samples survive the discard: the median spans them.
    assert res.rtt_ms == pytest.approx(statistics.median(res.samples))


async def test_tcp_probe_refused():
    # port 1 is reserved/closed on virtually every machine
    res = await tcp_probe("dead", "127.0.0.1", port=1, count=2, timeout_s=0.5)
    assert not res.success
    assert res.rtt_ms is None
    assert res.loss == 1.0
    assert res.error
