from nearest_exit.probes.icmp import parse_ping_output

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
