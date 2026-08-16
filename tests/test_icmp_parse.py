import sys

from nearest_exit.probes import icmp
from nearest_exit.probes.icmp import icmp_probe, parse_ping_output

MACOS_OUT = """\
PING 1.1.1.1 (1.1.1.1): 56 data bytes
64 bytes from 1.1.1.1: icmp_seq=0 ttl=58 time=12.345 ms
64 bytes from 1.1.1.1: icmp_seq=1 ttl=58 time=11.222 ms
64 bytes from 1.1.1.1: icmp_seq=2 ttl=58 time=13.000 ms

--- 1.1.1.1 ping statistics ---
3 packets transmitted, 3 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 11.222/12.189/13.000/0.732 ms
"""

LINUX_OUT = """\
PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
64 bytes from 1.1.1.1: icmp_seq=1 ttl=58 time=10.5 ms
64 bytes from 1.1.1.1: icmp_seq=2 ttl=58 time=9.7 ms
"""

NO_REPLY = """\
PING 192.0.2.1 (192.0.2.1): 56 data bytes
Request timeout for icmp_seq 0
"""


def test_parse_macos_three_samples():
    assert parse_ping_output(MACOS_OUT) == [12.345, 11.222, 13.000]


def test_parse_linux_two_samples():
    assert parse_ping_output(LINUX_OUT) == [10.5, 9.7]


def test_parse_no_reply():
    assert parse_ping_output(NO_REPLY) == []


def _fake_ping(monkeypatch, output: str) -> None:
    """Replace the ping invocation with a script that prints canned output."""
    monkeypatch.setattr(
        icmp, "_build_cmd",
        lambda ip, count, timeout_s: [sys.executable, "-c", f"print({output!r})"],
    )


async def test_probe_discards_cold_sample_when_nothing_was_lost(monkeypatch):
    # 3/3 replies → samples[0] really is the cold attempt; median of 11.222/13.0.
    _fake_ping(monkeypatch, MACOS_OUT)
    res = await icmp_probe("r", "1.1.1.1", count=3)
    assert res.success
    assert res.rtt_ms == 12.111
    assert res.loss == 0.0
    assert res.samples == (12.345, 11.222, 13.000)


async def test_probe_keeps_all_samples_when_a_packet_was_lost(monkeypatch):
    # 2 replies for 3 requested: the cold packet is the one that vanished,
    # so both surviving samples are warm and must be kept.
    _fake_ping(monkeypatch, LINUX_OUT)
    res = await icmp_probe("r", "1.1.1.1", count=3)
    assert res.rtt_ms == 10.1
    assert res.loss == 1.0 - (2 / 3)
    assert res.samples == (10.5, 9.7)


async def test_probe_keeps_single_sample(monkeypatch):
    _fake_ping(monkeypatch, LINUX_OUT)
    res = await icmp_probe("r", "1.1.1.1", count=2, discard_first=False)
    assert res.rtt_ms == 10.1
    assert res.loss == 0.0


async def test_probe_no_reply_is_total_loss(monkeypatch):
    _fake_ping(monkeypatch, NO_REPLY)
    res = await icmp_probe("r", "192.0.2.1", count=2)
    assert not res.success
    assert res.rtt_ms is None
    assert res.loss == 1.0
