from __future__ import annotations

import asyncio
import os
import socket
import statistics
import struct
import time

from ..models import ProbeResult
from . import summarise

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

# Transform identifiers, checked against the IANA IKEv2 registries rather than
# from memory: an earlier investigation in this project produced a phantom
# finding precisely because a notify-code table was typed out by hand.
ENCR_AES_CBC = 12
PRF_HMAC_SHA1 = 2
AUTH_HMAC_SHA1_96 = 2
ATTR_KEY_LENGTH_TV = 0x800E

# MODP-768, and the whole design rests on this choice. Group 1 carries a
# MUST NOT implementation status under RFC 8247, so a responder refusing it
# with NO_PROPOSAL_CHOSEN is following the spec rather than doing us a favour.
#
# Two structural consequences and one measured one:
#   - A refusal creates no security association, so it cannot contribute to the
#     half-open-SA count that RFC 7296 §2.6 cookies respond to.
#   - The reply is a bare Notify: a 28-byte header plus an 8-byte payload,
#     36 bytes against this 216-byte request. Smaller than what we sent, so the
#     probe is an unattractive reflector — though a spoofable UDP service is
#     never a strictly impossible one, and a responder that added NAT-D or
#     Vendor ID payloads would send more.
#   - An accepted exchange measured +2.7ms (PIA) to +6.0ms (NordVPN) slower on
#     the same host in the same round. That is the whole accept path, not an
#     isolated modexp — but it is load-dependent responder work either way, and
#     that is precisely the noise a latency comparison must not include.
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


# Only the SA payload is constant; the key-exchange value and the nonce are
# regenerated per request. RFC 7296 §2.10 requires Ni to be randomly chosen,
# and while a refused proposal is rejected before either is examined, sending
# fixed zeros is both a spec violation and a needless fingerprint. One urandom
# call covers the SPI, the KE value and the nonce together.
_SA = _sa_payload(PAYLOAD_KE)
_KE_HEADER = (
    struct.pack("!BBH", PAYLOAD_NONCE, 0, 8 + _KE_DATA_LEN)
    + struct.pack("!HH", DH_GROUP_MODP768, 0)
)
_NONCE_HEADER = struct.pack("!BBH", PAYLOAD_NONE, 0, 4 + _NONCE_LEN)
_ENTROPY_LEN = 8 + _KE_DATA_LEN + _NONCE_LEN

REQUEST_LEN = (
    HEADER_LEN
    + len(_SA)
    + len(_KE_HEADER) + _KE_DATA_LEN
    + len(_NONCE_HEADER) + _NONCE_LEN
)


def build_request(initiator_spi: bytes | None = None) -> bytes:
    """A minimal IKE_SA_INIT that every responder answers and none accepts.

    Assembled from parts rather than written out as a literal because every
    length field here is derived, and a hand-typed constant is exactly where
    those go wrong.
    """
    entropy = os.urandom(_ENTROPY_LEN)
    spi = entropy[:8] if initiator_spi is None else initiator_spi
    if len(spi) != 8:
        raise ValueError("initiator SPI must be 8 bytes")
    ke_data = entropy[8:8 + _KE_DATA_LEN]
    nonce = entropy[8 + _KE_DATA_LEN:]
    header = spi + bytes(8) + struct.pack(
        "!BBBBII",
        PAYLOAD_SA, IKE_VERSION, EXCHANGE_IKE_SA_INIT, FLAG_INITIATOR,
        0, REQUEST_LEN,
    )
    return header + _SA + _KE_HEADER + ke_data + _NONCE_HEADER + nonce


def is_ike_response(data: bytes, initiator_spi: bytes) -> bool:
    """True for any IKE_SA_INIT response to *our* exchange.

    Accept and refuse are equally valid: both took one round trip through the
    daemon, and for a latency probe the content of the reply is irrelevant.

    Deliberately does *not* require a non-zero responder SPI, even though
    RFC 7296 §3.1 says a response should carry one: every NO_PROPOSAL_CHOSEN
    observed from live responders has an all-zero R-SPI, because refusing
    creates no security association to name. Enforcing that rule would reject
    exactly the reply this probe is built around.
    """
    if len(data) < HEADER_LEN:
        return False
    if data[0:8] != initiator_spi:
        return False
    if data[17] != IKE_VERSION:
        return False
    if data[18] != EXCHANGE_IKE_SA_INIT:
        return False
    if not data[19] & FLAG_RESPONSE:
        return False
    if struct.unpack("!I", data[20:24])[0] != 0:      # message id of this exchange
        return False
    return struct.unpack("!I", data[24:28])[0] == len(data)


def is_accepted_response(data: bytes) -> bool:
    """True when the responder *accepted* the proposal instead of refusing it.

    Should never happen: the request offers only a group deprecated by
    RFC 8247. If it ever does, the measurement silently starts including the
    responder's Diffie-Hellman, so the caller labels it differently rather
    than folding it into the same column.
    """
    return len(data) > HEADER_LEN and data[16] == PAYLOAD_SA


async def _one(ip: str, port: int, timeout_s: float) -> tuple[float, bool] | None:
    """One request/response round trip, as (rtt_ms, accepted).

    Keeps reading until the deadline rather than judging the first datagram to
    arrive: a stray or spoofed packet on this ephemeral socket used to discard
    the whole sample, turning someone else's noise into apparent packet loss.
    """
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        packet = build_request()
        spi = packet[:8]
        start = time.perf_counter()
        await loop.sock_sendto(sock, packet, (ip, port))
        deadline = start + timeout_s
        while True:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                return None
            data, addr = await asyncio.wait_for(
                loop.sock_recvfrom(sock, 2048), timeout=remaining
            )
            if addr[0] != ip or addr[1] != port:
                continue
            if not is_ike_response(data, spi):
                continue
            elapsed = (time.perf_counter() - start) * 1000.0
            return elapsed, is_accepted_response(data)
    except (TimeoutError, OSError):
        return None
    finally:
        sock.close()


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
    results = [await _one(ip, port, timeout_s) for _ in range(count)]
    attempts: list[float | None] = [r[0] if r else None for r in results]
    # An acceptance measures a different code path — it includes the
    # responder's Diffie-Hellman — so it must not silently share a column with
    # a refusal. This is the design's one landmine: it fires only if a provider
    # starts accepting a group RFC 8247 deprecates.
    accepted = any(r[1] for r in results if r)

    samples = [a for a in attempts if a is not None]
    effective, counted, replied = summarise(attempts, discard_first)

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
        probe=f"ikev2-accepted/{port}" if accepted else f"ikev2/{port}",
        target=f"{ip}:{port}",
        success=success,
        rtt_ms=rtt,
        loss=max(0.0, min(1.0, loss)),
        jitter_ms=jitter,
        samples=tuple(samples),
        attempts=counted,
        error=error,
    )
