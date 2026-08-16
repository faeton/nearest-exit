from __future__ import annotations

import asyncio
import os
import socket
import statistics
import struct
import time

from ..models import ProbeResult

# OpenVPN control-channel opcodes, from the reliability layer's packet header:
# the top five bits of the first byte are the opcode, the low three the key id.
P_CONTROL_HARD_RESET_CLIENT_V2 = 7
P_CONTROL_HARD_RESET_SERVER_V2 = 8

def build_hard_reset(session_id: bytes | None = None) -> bytes:
    """The 14-byte packet that opens an OpenVPN control channel.

    Entirely plaintext — no keys, no handshake state, nothing to negotiate.
    That is what makes it usable as a probe: a server either answers it, or
    reads it and tears the connection down, and both are a round trip through
    the OpenVPN daemon rather than through the kernel's IP stack.
    """
    sid = session_id if session_id is not None else os.urandom(8)
    if len(sid) != 8:
        raise ValueError("session id must be 8 bytes")
    header = bytes([(P_CONTROL_HARD_RESET_CLIENT_V2 << 3) | 0])
    return header + sid + b"\x00" + struct.pack("!I", 0)


def is_server_reset(
    data: bytes, framed: bool = False, session_id: bytes | None = None
) -> bool:
    """True if `data` is the server's hard reset answering *our* session.

    `framed` accounts for the two-byte big-endian length TCP prepends.

    When `session_id` is given the reply must acknowledge it. The server's
    reset carries its own session id, then an ack array, then the session id
    it is acking — so one byte of opcode is not identification. Without this,
    any datagram whose first byte happens to land in 0x40-0x47 counted as a
    VPN daemon answering.
    """
    offset = 2 if framed else 0
    if len(data) <= offset:
        return False
    if (data[offset] >> 3) != P_CONTROL_HARD_RESET_SERVER_V2:
        return False
    if session_id is None:
        return True

    # opcode(1) their-session(8) ack-count(1) acked-packet-ids(4 each) ours(8)
    body = data[offset:]
    if len(body) < 10:
        return False
    acked = body[9]
    echo_at = 10 + 4 * acked
    if acked == 0 or len(body) < echo_at + 8:
        return False
    return body[echo_at:echo_at + 8] == session_id


async def _one_udp(ip: str, port: int, timeout_s: float) -> tuple[float, bool] | None:
    """One control-channel round trip, as (rtt_ms, got_a_real_reply)."""
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        session = os.urandom(8)
        packet = build_hard_reset(session)
        start = time.perf_counter()
        await loop.sock_sendto(sock, packet, (ip, port))
        deadline = start + timeout_s
        # Keep reading rather than judging the first datagram: a stray packet
        # on this socket should not cost us the sample.
        while True:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                return None
            data, addr = await asyncio.wait_for(
                loop.sock_recvfrom(sock, 2048), timeout=remaining
            )
            if addr[0] != ip or addr[1] != port:
                continue
            if not is_server_reset(data, session_id=session):
                continue
            return (time.perf_counter() - start) * 1000.0, True
    except (TimeoutError, OSError):
        return None
    finally:
        sock.close()


async def _one_tcp(ip: str, port: int, timeout_s: float) -> tuple[float, bool] | None:
    """Time one control-channel round trip over TCP.

    Returns (rtt_ms, got_a_real_reply). Providers running `tls-auth` or
    `tls-crypt` will not answer an unauthenticated reset, but they do read it,
    fail the HMAC and close. Both outcomes are timed from the moment the packet
    goes out, so the number is a round trip either way — but they are not the
    same evidence, and the caller labels them differently. A close only says
    "something accepted a connection and hung up after 16 bytes", which a TLS
    terminator or a proxy on 443 will also do; a reset reply identifies an
    OpenVPN daemon.

    The connect that precedes it is deliberately not counted: it completes in
    the kernel before the daemon is scheduled, which is exactly the thing this
    probe exists to see past. One deadline covers connect, write and read, so a
    slow host cannot cost three full timeouts.
    """
    deadline = time.perf_counter() + timeout_s

    def left() -> float:
        return deadline - time.perf_counter()

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=max(left(), 0.001)
        )
    except (TimeoutError, OSError):
        return None
    try:
        try:
            writer.transport.get_extra_info("socket").setsockopt(
                socket.IPPROTO_TCP, socket.TCP_NODELAY, 1
            )
        except (AttributeError, OSError):
            pass
        session = os.urandom(8)
        packet = build_hard_reset(session)
        start = time.perf_counter()
        writer.write(struct.pack("!H", len(packet)) + packet)
        await asyncio.wait_for(writer.drain(), timeout=max(left(), 0.001))
        data = await asyncio.wait_for(reader.read(2048), timeout=max(left(), 0.001))
        elapsed = (time.perf_counter() - start) * 1000.0
        if not data:
            return elapsed, False          # clean close: weaker evidence
        if is_server_reset(data, framed=True, session_id=session):
            return elapsed, True
        return None
    except (TimeoutError, OSError, ConnectionError):
        return None
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except (OSError, ConnectionError):
            pass


def _warm_samples(attempts: list[float | None], discard_first: bool) -> list[float]:
    """Successful RTTs with the cold attempt dropped.

    The cold sample is whatever came back from the *first attempt*, not the
    first success: when the opening attempt is lost there is nothing cold left
    to discard.
    """
    ok = [a for a in attempts if a is not None]
    if discard_first and attempts and attempts[0] is not None and len(ok) >= 2:
        return ok[1:]
    return ok


async def openvpn_probe(
    relay_id: str,
    ip: str,
    port: int = 1194,
    count: int = 3,
    timeout_s: float = 2.0,
    discard_first: bool = True,
    transport: str = "udp",
) -> ProbeResult:
    """Probe a relay's OpenVPN control channel.

    Unlike ICMP or a bare TCP connect, this measures the VPN daemon answering
    as a VPN daemon. A relay can reply to ping quickly while its OpenVPN
    process is loaded, throttled or routed differently.
    """
    one = _one_udp if transport == "udp" else _one_tcp
    results = [await one(ip, port, timeout_s) for _ in range(count)]
    attempts: list[float | None] = [r[0] if r else None for r in results]
    # A close is a round trip but not an identification: only a reset reply
    # proves an OpenVPN daemon was on the other end. Kept visible in the probe
    # label rather than blended into one number.
    identified = any(r[1] for r in results if r)

    samples = [a for a in attempts if a is not None]
    if discard_first and count >= 2:
        # The first attempt pays for route setup and, over TCP, for the
        # connection itself, so it is excluded from the denominator as well as
        # from the median — the same rule the ICMP probe uses.
        counted = count - 1
        replied = sum(1 for a in attempts[1:] if a is not None)
        effective = _warm_samples(attempts, discard_first)
    else:
        counted = count
        replied = len(samples)
        effective = samples

    success = len(effective) > 0
    if success:
        rtt = statistics.median(effective)
        jitter = statistics.pstdev(effective) if len(effective) >= 2 else 0.0
        loss = 1.0 - (replied / counted) if counted else 0.0
        error = None
    else:
        rtt = None
        jitter = None
        loss = 1.0
        error = f"no openvpn control reply on {transport}/{port}"

    kind = f"openvpn-{transport}" if identified else f"openvpn-{transport}-close"
    return ProbeResult(
        relay_id=relay_id,
        probe=f"{kind}/{port}",
        target=f"{ip}:{port}",
        success=success,
        rtt_ms=rtt,
        loss=max(0.0, min(1.0, loss)),
        jitter_ms=jitter,
        samples=tuple(samples),
        attempts=counted,
        error=error,
    )
