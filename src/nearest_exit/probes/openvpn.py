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

# Session id (8) + ack array length (1) + packet id (4), after the opcode byte.
_RESET_LEN = 14


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


def is_server_reset(data: bytes, framed: bool = False) -> bool:
    """True if `data` is the server's matching hard reset.

    `framed` accounts for the two-byte big-endian length TCP prepends.
    """
    offset = 2 if framed else 0
    if len(data) <= offset:
        return False
    return (data[offset] >> 3) == P_CONTROL_HARD_RESET_SERVER_V2


async def _one_udp(ip: str, port: int, timeout_s: float) -> float | None:
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        packet = build_hard_reset()
        start = time.perf_counter()
        await loop.sock_sendto(sock, packet, (ip, port))
        data, addr = await asyncio.wait_for(
            loop.sock_recvfrom(sock, 2048), timeout=timeout_s
        )
        elapsed = (time.perf_counter() - start) * 1000.0
        if addr[0] != ip or not is_server_reset(data):
            return None
        return elapsed
    except (TimeoutError, OSError):
        return None
    finally:
        sock.close()


async def _one_tcp(ip: str, port: int, timeout_s: float) -> float | None:
    """Time one control-channel round trip over TCP.

    Providers running `tls-auth` or `tls-crypt` will not answer an
    unauthenticated reset, but they do read it, fail the HMAC and close. Both
    outcomes are timed from the moment the packet goes out, so the number is a
    daemon round trip either way. The connect that precedes it is deliberately
    not counted: it completes in the kernel, before the daemon is scheduled,
    which is exactly the thing this probe exists to see past.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout_s
        )
    except (TimeoutError, OSError):
        return None
    try:
        packet = build_hard_reset()
        start = time.perf_counter()
        writer.write(struct.pack("!H", len(packet)) + packet)
        await asyncio.wait_for(writer.drain(), timeout=timeout_s)
        # Either a framed reply or EOF. A server that holds the connection open
        # never read our bytes, so a timeout is a failure, not a slow success.
        data = await asyncio.wait_for(reader.read(2048), timeout=timeout_s)
        elapsed = (time.perf_counter() - start) * 1000.0
        if data and not is_server_reset(data, framed=True):
            return None
        return elapsed
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
    attempts: list[float | None] = []
    for _ in range(count):
        attempts.append(await one(ip, port, timeout_s))

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

    return ProbeResult(
        relay_id=relay_id,
        probe=f"openvpn-{transport}/{port}",
        target=f"{ip}:{port}",
        success=success,
        rtt_ms=rtt,
        loss=max(0.0, min(1.0, loss)),
        jitter_ms=jitter,
        samples=tuple(samples),
        attempts=counted,
        error=error,
    )
