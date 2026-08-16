import asyncio
import socket
import struct

import pytest

from nearest_exit.probes.openvpn import (
    P_CONTROL_HARD_RESET_CLIENT_V2,
    P_CONTROL_HARD_RESET_SERVER_V2,
    _warm_samples,
    build_hard_reset,
    is_server_reset,
    openvpn_probe,
)


def test_hard_reset_is_the_documented_14_bytes():
    packet = build_hard_reset(b"01234567")
    assert len(packet) == 14
    assert packet[0] >> 3 == P_CONTROL_HARD_RESET_CLIENT_V2
    assert packet[0] & 0b111 == 0                      # key id 0
    assert packet[1:9] == b"01234567"                  # session id
    assert packet[9] == 0                              # empty ack array
    assert struct.unpack("!I", packet[10:14])[0] == 0  # packet id


def test_hard_reset_session_ids_differ_between_packets():
    assert build_hard_reset() != build_hard_reset()


def test_hard_reset_rejects_a_wrong_length_session_id():
    with pytest.raises(ValueError):
        build_hard_reset(b"short")


def _server_reset(client_session: bytes = b"\x00" * 8) -> bytes:
    """The reply a real server sends: its own session id, then an ack array
    acknowledging our packet 0, then *our* session id echoed back."""
    return (
        bytes([(P_CONTROL_HARD_RESET_SERVER_V2 << 3) | 0])
        + b"\xAA" * 8                       # the server's own session id
        + b"\x01"                           # one acked packet id follows
        + struct.pack("!I", 0)              # ...which is our packet id 0
        + client_session                    # our session id, echoed
        + struct.pack("!I", 0)              # the server's own packet id
    )


def test_server_reset_is_recognised_framed_and_unframed():
    body = _server_reset()
    assert is_server_reset(body)
    assert not is_server_reset(body, framed=True)

    framed = struct.pack("!H", len(body)) + body
    assert is_server_reset(framed, framed=True)
    assert not is_server_reset(framed)


def test_a_client_reset_echoed_back_is_not_a_server_reset():
    assert not is_server_reset(build_hard_reset())
    assert not is_server_reset(b"")


def test_warm_samples_drops_the_cold_attempt_only_when_it_answered():
    assert _warm_samples([10.0, 5.0, 6.0], True) == [5.0, 6.0]
    assert _warm_samples([None, 5.0, 6.0], True) == [5.0, 6.0]
    assert _warm_samples([10.0, None, None], True) == [10.0]
    assert _warm_samples([10.0, 5.0], False) == [10.0, 5.0]


# --- UDP: a server that answers, like PIA ------------------------------------


async def _udp_responder(reply: bytes | None, echo_session: bool = True):
    """Bind a UDP socket answering each datagram, or ignoring it.

    `echo_session=False` answers without acknowledging our session id, which is
    what an unrelated service on the port looks like."""
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.setblocking(False)
    stop = asyncio.Event()

    async def serve():
        while not stop.is_set():
            try:
                data, addr = await asyncio.wait_for(loop.sock_recvfrom(sock, 2048), 0.5)
            except (TimeoutError, OSError):
                continue
            assert data[0] >> 3 == P_CONTROL_HARD_RESET_CLIENT_V2
            if reply is not None:
                out = _server_reset(data[1:9]) if echo_session else reply
                await loop.sock_sendto(sock, out, addr)

    task = asyncio.create_task(serve())
    return sock.getsockname()[1], sock, stop, task


async def _shutdown(sock, stop, task):
    stop.set()
    task.cancel()
    try:
        await task
    except (asyncio.CancelledError, Exception):
        pass
    sock.close()


async def test_udp_probe_times_a_server_reset():
    port, sock, stop, task = await _udp_responder(_server_reset())
    try:
        res = await openvpn_probe("r", "127.0.0.1", port=port, count=3, timeout_s=2.0)
    finally:
        await _shutdown(sock, stop, task)

    assert res.success
    assert res.probe == f"openvpn-udp/{port}"
    assert res.target == f"127.0.0.1:{port}"
    assert res.loss == 0.0
    assert res.rtt_ms is not None
    # The cold attempt is excluded from the denominator as well as the median.
    assert res.attempts == 2


async def test_udp_probe_fails_when_the_daemon_stays_silent():
    port, sock, stop, task = await _udp_responder(None)
    try:
        res = await openvpn_probe("r", "127.0.0.1", port=port, count=2, timeout_s=0.3)
    finally:
        await _shutdown(sock, stop, task)

    assert not res.success
    assert res.loss == 1.0
    assert res.rtt_ms is None
    assert "no openvpn control reply" in res.error


async def test_udp_probe_rejects_a_reply_that_is_not_a_reset():
    """Something answering on the port is not the same as OpenVPN answering."""
    port, sock, stop, task = await _udp_responder(b"\x00" * 26, echo_session=False)
    try:
        res = await openvpn_probe("r", "127.0.0.1", port=port, count=2, timeout_s=0.3)
    finally:
        await _shutdown(sock, stop, task)

    assert not res.success


# --- TCP: a server that reads and closes, like AirVPN and NordVPN ------------


async def _tcp_server(behaviour: str):
    async def handle(reader, writer):
        data = await reader.read(64)
        assert data[2] >> 3 == P_CONTROL_HARD_RESET_CLIENT_V2
        if behaviour == "reply":
            body = _server_reset(data[3:11])
            writer.write(struct.pack("!H", len(body)) + body)
            await writer.drain()
        elif behaviour == "hold":
            await asyncio.sleep(5)
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server.sockets[0].getsockname()[1], server


async def test_tcp_probe_times_a_close_as_a_daemon_round_trip():
    """tls-auth providers never answer, but they read the packet and tear the
    connection down, which is still a round trip through the daemon."""
    port, server = await _tcp_server("close")
    try:
        res = await openvpn_probe(
            "r", "127.0.0.1", port=port, count=3, timeout_s=2.0, transport="tcp",
        )
    finally:
        server.close()
        await server.wait_closed()

    assert res.success
    # A close is a round trip but not an identification, and the label says so.
    assert res.probe == f"openvpn-tcp-close/{port}"
    assert res.loss == 0.0


async def test_tcp_probe_accepts_an_actual_reply_too():
    port, server = await _tcp_server("reply")
    try:
        res = await openvpn_probe(
            "r", "127.0.0.1", port=port, count=2, timeout_s=2.0, transport="tcp",
        )
    finally:
        server.close()
        await server.wait_closed()

    assert res.success
    # A reset reply identifies an OpenVPN daemon; a bare close does not.
    assert res.probe == f"openvpn-tcp/{port}"


async def test_a_reply_that_does_not_acknowledge_our_session_is_not_ours():
    """One byte of opcode is not identification: any datagram whose first byte
    lands in 0x40-0x47 used to count as a VPN daemon answering."""
    ours, theirs = b"\x11" * 8, b"\x22" * 8
    assert is_server_reset(_server_reset(ours), session_id=ours)
    assert not is_server_reset(_server_reset(theirs), session_id=ours)
    # Opcode alone still passes when no correlation is requested.
    assert is_server_reset(_server_reset(theirs))


async def test_udp_probe_rejects_a_reset_for_someone_elses_session():
    port, sock, stop, task = await _udp_responder(
        _server_reset(b"\x33" * 8), echo_session=False
    )
    try:
        res = await openvpn_probe("r", "127.0.0.1", port=port, count=2, timeout_s=0.3)
    finally:
        await _shutdown(sock, stop, task)

    assert not res.success


async def test_tcp_probe_fails_when_the_connection_is_merely_held_open():
    """A server that accepts and then ignores us never read our bytes, so a
    timeout is a failure rather than a slow success."""
    port, server = await _tcp_server("hold")
    try:
        res = await openvpn_probe(
            "r", "127.0.0.1", port=port, count=1, timeout_s=0.3, transport="tcp",
        )
    finally:
        server.close()
        await server.wait_closed()

    assert not res.success


async def test_tcp_probe_fails_on_a_closed_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    res = await openvpn_probe(
        "r", "127.0.0.1", port=port, count=1, timeout_s=0.5, transport="tcp",
    )
    assert not res.success
    assert res.rtt_ms is None
