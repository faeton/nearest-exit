import sys

import pytest

from nearest_exit.probes import icmp
from nearest_exit.probes.icmp import (
    icmp_probe,
    parse_ping_output,
    parse_ping_replies,
    warm_samples,
)

# BSD ping numbers packets from 0, GNU ping from 1. Every test below states
# which convention it is exercising, so the suite means the same thing on
# either platform.
BSD_FIRST_SEQ = 0
GNU_FIRST_SEQ = 1

MACOS_OUT = """\
PING 1.1.1.1 (1.1.1.1): 56 data bytes
64 bytes from 1.1.1.1: icmp_seq=0 ttl=58 time=12.345 ms
64 bytes from 1.1.1.1: icmp_seq=1 ttl=58 time=11.222 ms
64 bytes from 1.1.1.1: icmp_seq=2 ttl=58 time=13.000 ms

--- 1.1.1.1 ping statistics ---
3 packets transmitted, 3 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 11.222/12.189/13.000/0.732 ms
"""

# The cold packet came back; a later one did not. Discarding by position
# would have kept the cold sample and thrown away a warm one.
MACOS_LATE_LOSS = """\
PING 1.1.1.1 (1.1.1.1): 56 data bytes
64 bytes from 1.1.1.1: icmp_seq=0 ttl=58 time=100.0 ms
64 bytes from 1.1.1.1: icmp_seq=1 ttl=58 time=10.0 ms
Request timeout for icmp_seq 2
"""

# The cold packet was lost, so both survivors are warm and must be kept.
MACOS_COLD_LOSS = """\
PING 1.1.1.1 (1.1.1.1): 56 data bytes
Request timeout for icmp_seq 0
64 bytes from 1.1.1.1: icmp_seq=1 ttl=58 time=10.5 ms
64 bytes from 1.1.1.1: icmp_seq=2 ttl=58 time=9.7 ms
"""

LINUX_OUT = """\
PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
64 bytes from 1.1.1.1: icmp_seq=1 ttl=58 time=10.5 ms
64 bytes from 1.1.1.1: icmp_seq=2 ttl=58 time=9.7 ms
"""

# Windows ping prints no sequence numbers at all.
WINDOWS_OUT = """\
Reply from 1.1.1.1: bytes=32 time=12ms TTL=58
Reply from 1.1.1.1: bytes=32 time=11ms TTL=58
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


def test_parse_replies_carries_sequence_numbers():
    assert parse_ping_replies(MACOS_OUT) == [(0, 12.345), (1, 11.222), (2, 13.0)]
    assert parse_ping_replies(LINUX_OUT) == [(1, 10.5), (2, 9.7)]


def test_parse_replies_empty_when_ping_prints_no_sequence_numbers():
    assert parse_ping_replies(WINDOWS_OUT) == []
    assert parse_ping_output(WINDOWS_OUT) == [12.0, 11.0]


def test_warm_samples_drops_the_cold_packet_by_sequence_not_position():
    replies = parse_ping_replies(MACOS_LATE_LOSS)
    assert warm_samples(replies, first_seq=BSD_FIRST_SEQ) == [10.0]


def test_warm_samples_keeps_everything_when_the_cold_packet_was_lost():
    replies = parse_ping_replies(MACOS_COLD_LOSS)
    assert warm_samples(replies, first_seq=BSD_FIRST_SEQ) == [10.5, 9.7]


def test_warm_samples_honours_the_gnu_convention():
    replies = parse_ping_replies(LINUX_OUT)
    assert warm_samples(replies, first_seq=GNU_FIRST_SEQ) == [9.7]
    assert warm_samples(replies, first_seq=BSD_FIRST_SEQ) == [10.5, 9.7]


def test_warm_samples_never_returns_empty():
    assert warm_samples([(0, 5.0)], first_seq=BSD_FIRST_SEQ) == [5.0]
    assert warm_samples([], first_seq=BSD_FIRST_SEQ) == []


def _fake_ping(monkeypatch, output: str, first_seq: int = BSD_FIRST_SEQ) -> None:
    """Run a canned ping output through the real probe, pinning the platform's
    sequence-numbering convention so the assertion means one thing."""
    monkeypatch.setattr(
        icmp, "_build_cmd",
        lambda ip, count, timeout_s: [sys.executable, "-c", f"print({output!r})"],
    )
    monkeypatch.setattr(icmp, "FIRST_SEQ", first_seq)


async def test_probe_discards_cold_sample_when_nothing_was_lost(monkeypatch):
    _fake_ping(monkeypatch, MACOS_OUT)
    res = await icmp_probe("r", "1.1.1.1", count=3)
    assert res.success
    assert res.rtt_ms == 12.111
    assert res.loss == 0.0
    assert res.samples == (12.345, 11.222, 13.000)
    # The warm-up packet is excluded from the denominator as well as the median.
    assert res.attempts == 2


async def test_probe_discards_cold_sample_even_when_a_later_packet_was_lost(monkeypatch):
    """The old rule assumed any loss meant the cold packet was the missing
    one, so this reported a 55ms median instead of the warm 10ms."""
    _fake_ping(monkeypatch, MACOS_LATE_LOSS)
    res = await icmp_probe("r", "1.1.1.1", count=3)
    assert res.rtt_ms == 10.0
    # Two warm packets sent, one replied.
    assert res.loss == pytest.approx(0.5)
    assert res.attempts == 2


async def test_losing_the_warm_up_packet_is_not_charged_as_loss(monkeypatch):
    """Discarding the first packet\'s RTT because it pays for ARP and route
    setup, then charging a loss penalty when that same packet is the one that
    dropped, is the tool arguing with itself."""
    _fake_ping(monkeypatch, MACOS_COLD_LOSS)
    res = await icmp_probe("r", "1.1.1.1", count=3)
    assert res.rtt_ms == 10.1
    assert res.loss == 0.0
    assert res.attempts == 2
    assert res.samples == (10.5, 9.7)


async def test_probe_without_sequence_numbers_falls_back_to_position(monkeypatch):
    _fake_ping(monkeypatch, WINDOWS_OUT)
    res = await icmp_probe("r", "1.1.1.1", count=2)
    # Complete run, so the first reply really is the cold attempt.
    assert res.rtt_ms == 11.0
    assert res.samples == (12.0, 11.0)


async def test_probe_keeps_single_sample(monkeypatch):
    _fake_ping(monkeypatch, LINUX_OUT, first_seq=GNU_FIRST_SEQ)
    res = await icmp_probe("r", "1.1.1.1", count=2, discard_first=False)
    assert res.rtt_ms == 10.1
    assert res.loss == 0.0


async def test_probe_no_reply_is_total_loss(monkeypatch):
    _fake_ping(monkeypatch, NO_REPLY)
    res = await icmp_probe("r", "192.0.2.1", count=2)
    assert not res.success
    assert res.rtt_ms is None
    assert res.loss == 1.0
    # Nothing replied, so there was no warm-up to discard and all packets count.
    assert res.attempts == 2


ONLY_COLD_REPLIED = """\
PING 1.1.1.1 (1.1.1.1): 56 data bytes
64 bytes from 1.1.1.1: icmp_seq=0 ttl=58 time=40.0 ms
Request timeout for icmp_seq 1
Request timeout for icmp_seq 2
"""


async def test_a_lone_cold_reply_is_not_reported_as_total_loss(monkeypatch):
    """Discarding the warm-up when it is the *only* reply left a result that
    was successful and simultaneously claimed every counted packet was lost."""
    _fake_ping(monkeypatch, ONLY_COLD_REPLIED)
    res = await icmp_probe("r", "1.1.1.1", count=3)

    assert res.success
    assert res.rtt_ms == 40.0
    # All three packets count, and two of them really were lost.
    assert res.attempts == 3
    assert res.loss == pytest.approx(2 / 3)
