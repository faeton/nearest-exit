from __future__ import annotations

import asyncio
import os
import socket
import statistics
import struct
import time

from ..models import ProbeResult

# RFC 7296 §3.1. The request is fixed-layout plaintext throughout — there is no
# cryptography anywhere in it, which is what makes this usable as a probe.
IKE_VERSION = 0x20              # major 2, minor 0
EXCHANGE_IKE_SA_INIT = 34
FLAG_INITIATOR = 0x08
FLAG_RESPONSE = 0x20
HEADER_LEN = 28

PAYLOAD_NONE = 0
PAYLOAD_SA = 33
PAYLOAD_KE = 34
PAYLOAD_NONCE = 40

TRANSFORM_ENCR = 1
TRANSFORM_PRF = 2
TRANSFORM_INTEG = 3
TRANSFORM_DH = 4

ENCR_AES_CBC = 12
PRF_HMAC_SHA1 = 2
AUTH_HMAC_SHA1_96 = 2
ATTR_KEY_LENGTH_TV = 0x800E

# MODP-768, and the whole design rests on this choice. Every current responder
# refuses group 1 with NO_PROPOSAL_CHOSEN, and a refusal is a full round trip
# through the daemon that costs it no Diffie-Hellman and creates no half-open
# SA. That matters three ways: an accepted exchange bakes the responder's
# 2048-bit modexp into the measured RTT (+2.7ms to +6.0ms, varying with how
# loaded the relay is, which is exactly the noise a latency probe must not
# add); three back-to-back samples of an accepted exchange trip RFC 7296 §2.6
# cookie machinery while a refused one never does; and the reply is 36 bytes
# against a 216-byte request, so the probe cannot be turned into a reflector.
DH_GROUP_MODP768 = 1
_KE_DATA_LEN = 96
_NONCE_LEN = 32

UDP_PORT = 500


def _transform(last: bool, ttype: int, tid: int, attrs: bytes = b"") -> bytes:
    return struct.pack(
        "!BBHBBH", 0 if last else 3, 0, 8 + len(attrs), ttype, 0, tid
    ) + attrs


def _sa_payload(next_payload: int) -> bytes:
    transforms = (
        _transform(False, TRANSFORM_ENCR, ENCR_AES_CBC,
                   struct.pack("!HH", ATTR_KEY_LENGTH_TV, 128))
        + _transform(False, TRANSFORM_PRF, PRF_HMAC_SHA1)
        + _transform(False, TRANSFORM_INTEG, AUTH_HMAC_SHA1_96)
        + _transform(True, TRANSFORM_DH, DH_GROUP_MODP768)
    )
    # Proposal: last, RESERVED, length, number, protocol IKE, SPI size 0, count.
    proposal = struct.pack("!BBHBBBB", 0, 0, 8 + len(transforms), 1, 1, 0, 4)
    proposal += transforms
    return struct.pack("!BBH", next_payload, 0, 4 + len(proposal)) + proposal


def _ke_payload(next_payload: int) -> bytes:
    # The responder does not validate the group element before replying, so
    # filler is as good as a real g^x — and group 1 is refused before the value
    # is ever looked at.
    body = struct.pack("!HH", DH_GROUP_MODP768, 0) + bytes(_KE_DATA_LEN)
    return struct.pack("!BBH", next_payload, 0, 4 + len(body)) + body


def _nonce_payload(next_payload: int) -> bytes:
    body = bytes(_NONCE_LEN)
    return struct.pack("!BBH", next_payload, 0, 4 + len(body)) + body


# Everything after the initiator SPI is constant, so a probe costs one 8-byte
# urandom read. Assembled from parts rather than written out as a literal
# because every length field here is derived, and a hand-typed constant is
# exactly where those go wrong.
_BODY = (
    _sa_payload(PAYLOAD_KE)
    + _ke_payload(PAYLOAD_NONCE)
    + _nonce_payload(PAYLOAD_NONE)
)
REQUEST_LEN = HEADER_LEN + len(_BODY)


def build_request(initiator_spi: bytes | None = None) -> bytes:
    """A minimal IKE_SA_INIT that every responder answers and none accepts."""
    spi = initiator_spi if initiator_spi is not None else os.urandom(8)
    if len(spi) != 8:
        raise ValueError("initiator SPI must be 8 bytes")
    header = spi + bytes(8) + struct.pack(
        "!BBBBII",
        PAYLOAD_SA, IKE_VERSION, EXCHANGE_IKE_SA_INIT, FLAG_INITIATOR,
        0, REQUEST_LEN,
    )
    return header + _BODY


def is_ike_response(data: bytes, initiator_spi: bytes) -> bool:
    """True for any IKE_SA_INIT response to *our* exchange.

    Accept and refuse are equally valid: both took one round trip through the
    daemon, and for a latency probe the content of the reply is irrelevant.
    What matters is that it is ours — the SPI echo is what distinguishes a real
    answer from a stray datagram.
    """
    if len(data) < HEADER_LEN:
        return False
    if data[0:8] != initiator_spi:
        return False
    if data[18] != EXCHANGE_IKE_SA_INIT:
        return False
    return bool(data[19] & FLAG_RESPONSE)


async def _one(ip: str, port: int, timeout_s: float) -> float | None:
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        spi = os.urandom(8)
        packet = build_request(spi)
        start = time.perf_counter()
        await loop.sock_sendto(sock, packet, (ip, port))
        data, addr = await asyncio.wait_for(
            loop.sock_recvfrom(sock, 2048), timeout=timeout_s
        )
        elapsed = (time.perf_counter() - start) * 1000.0
        if addr[0] != ip or not is_ike_response(data, spi):
            return None
        return elapsed
    except (TimeoutError, OSError):
        return None
    finally:
        sock.close()


def _warm_samples(attempts: list[float | None], discard_first: bool) -> list[float]:
    ok = [a for a in attempts if a is not None]
    if discard_first and attempts and attempts[0] is not None and len(ok) >= 2:
        return ok[1:]
    return ok


async def ike_probe(
    relay_id: str,
    ip: str,
    port: int = UDP_PORT,
    count: int = 3,
    timeout_s: float = 2.0,
    discard_first: bool = True,
) -> ProbeResult:
    """Time an IKEv2 daemon refusing an unauthenticated proposal.

    One UDP datagram out, one back, on the plane IKEv2 actually runs on. The
    daemon has to parse an SA payload and match it against its configured
    proposals to decide to refuse, so the round trip is a real daemon round
    trip rather than a kernel one.
    """
    attempts: list[float | None] = []
    for _ in range(count):
        attempts.append(await _one(ip, port, timeout_s))

    samples = [a for a in attempts if a is not None]
    if discard_first and count >= 2:
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
        error = f"no IKE_SA_INIT response on udp/{port}"

    return ProbeResult(
        relay_id=relay_id,
        probe=f"ikev2/{port}",
        target=f"{ip}:{port}",
        success=success,
        rtt_ms=rtt,
        loss=max(0.0, min(1.0, loss)),
        jitter_ms=jitter,
        samples=tuple(samples),
        attempts=counted,
        error=error,
    )
