import asyncio
import socket
import struct

import pytest

from nearest_exit.models import Relay
from nearest_exit.probes.ike import (
    DH_GROUP_MODP768,
    EXCHANGE_IKE_SA_INIT,
    FLAG_INITIATOR,
    FLAG_RESPONSE,
    HEADER_LEN,
    IKE_VERSION,
    PAYLOAD_SA,
    REQUEST_LEN,
    build_request,
    ike_probe,
    is_ike_response,
)
from nearest_exit.targets import ikev2_targets


def test_request_header_matches_rfc_7296():
    req = build_request(b"\x01" * 8)

    assert req[0:8] == b"\x01" * 8          # initiator SPI
    assert req[8:16] == bytes(8)            # responder SPI is zero in a request
    assert req[16] == PAYLOAD_SA
    assert req[17] == IKE_VERSION
    assert req[18] == EXCHANGE_IKE_SA_INIT
    assert req[19] == FLAG_INITIATOR
    assert struct.unpack("!I", req[20:24])[0] == 0   # message id
    assert struct.unpack("!I", req[24:28])[0] == len(req)


def test_payload_chain_closes_exactly_at_the_end_of_the_packet():
    """Every length here is derived, and a hand-typed constant is exactly where
    those go wrong — so walk the chain the way a responder would."""
    req = build_request(b"\x02" * 8)
    offset, next_payload = HEADER_LEN, req[16]
    seen = []
    while next_payload:
        following = req[offset]
        length = struct.unpack("!H", req[offset + 2:offset + 4])[0]
        assert length >= 4
        seen.append((next_payload, length))
        offset += length
        next_payload = following

    assert offset == len(req) == REQUEST_LEN
    assert [p for p, _ in seen] == [33, 34, 40]      # SA, KE, Nonce


def test_request_proposes_only_the_group_every_responder_refuses():
    """Group 1 is the whole design: a refusal is a full daemon round trip that
    costs no Diffie-Hellman, creates no half-open SA, and cannot be amplified."""
    req = build_request(b"\x03" * 8)
    # KE payload declares the group in its first two body bytes.
    ke_offset = HEADER_LEN + struct.unpack("!H", req[HEADER_LEN + 2:HEADER_LEN + 4])[0]
    assert struct.unpack("!H", req[ke_offset + 4:ke_offset + 6])[0] == DH_GROUP_MODP768
    # Response is 36 bytes against this; anything much larger would amplify.
    assert REQUEST_LEN == 216


def test_request_spi_is_random_per_probe():
    assert build_request()[0:8] != build_request()[0:8]


def test_request_rejects_a_wrong_length_spi():
    with pytest.raises(ValueError):
        build_request(b"short")


def _response(spi: bytes, exchange: int = EXCHANGE_IKE_SA_INIT,
              flags: int = FLAG_RESPONSE) -> bytes:
    return spi + b"\x09" * 8 + struct.pack(
        "!BBBBII", 0, IKE_VERSION, exchange, flags, 0, HEADER_LEN
    )


def test_a_reply_counts_only_when_it_echoes_our_exchange():
    spi = b"\x04" * 8
    assert is_ike_response(_response(spi), spi)

    assert not is_ike_response(_response(b"\x05" * 8), spi)          # someone else's
    assert not is_ike_response(_response(spi, exchange=35), spi)     # not SA_INIT
    assert not is_ike_response(_response(spi, flags=FLAG_INITIATOR), spi)
    assert not is_ike_response(b"", spi)
    assert not is_ike_response(b"\x00" * 10, spi)


def test_refusal_and_acceptance_are_both_valid_measurements():
    """Both took one round trip through the daemon; the content is irrelevant."""
    spi = b"\x06" * 8
    refusal = _response(spi) + b"\x29\x00\x00\x08\x00\x00\x00\x0e"   # N:NO_PROPOSAL
    acceptance = _response(spi) + b"\x21\x00\x01\x00" + bytes(252)
    assert is_ike_response(refusal, spi)
    assert is_ike_response(acceptance, spi)


# --- live-shaped tests against a local responder ------------------------------


async def _responder(mode: str):
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
            assert data[18] == EXCHANGE_IKE_SA_INIT
            if mode == "refuse":
                await loop.sock_sendto(sock, _response(data[0:8]), addr)
            elif mode == "wrong-spi":
                await loop.sock_sendto(sock, _response(b"\xff" * 8), addr)
            elif mode == "garbage":
                await loop.sock_sendto(sock, b"\x00" * 40, addr)

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


async def test_probe_times_a_refusal():
    port, sock, stop, task = await _responder("refuse")
    try:
        res = await ike_probe("r", "127.0.0.1", port=port, count=3, timeout_s=2.0)
    finally:
        await _shutdown(sock, stop, task)

    assert res.success
    assert res.probe == f"ikev2/{port}"
    assert res.loss == 0.0
    assert res.attempts == 2      # warm-up excluded from the denominator


async def test_probe_ignores_a_reply_to_someone_elses_exchange():
    port, sock, stop, task = await _responder("wrong-spi")
    try:
        res = await ike_probe("r", "127.0.0.1", port=port, count=2, timeout_s=0.3)
    finally:
        await _shutdown(sock, stop, task)

    assert not res.success


async def test_probe_ignores_non_ike_noise_on_the_port():
    port, sock, stop, task = await _responder("garbage")
    try:
        res = await ike_probe("r", "127.0.0.1", port=port, count=2, timeout_s=0.3)
    finally:
        await _shutdown(sock, stop, task)

    assert not res.success


async def test_probe_fails_on_silence():
    port, sock, stop, task = await _responder("silent")
    try:
        res = await ike_probe("r", "127.0.0.1", port=port, count=2, timeout_s=0.3)
    finally:
        await _shutdown(sock, stop, task)

    assert not res.success
    assert res.loss == 1.0
    assert "no IKE_SA_INIT response" in res.error


# --- targeting ----------------------------------------------------------------


def _relay(provider: str, protocols: tuple[str, ...]) -> Relay:
    return Relay(provider=provider, id="r", hostname="r.example.net",
                 ipv4="203.0.113.1", protocols=protocols)


def test_ikev2_targets_are_nordvpn_only():
    targets = ikev2_targets(_relay("nordvpn", ("wireguard", "openvpn", "ikev2")))
    assert [(t.host, t.port, t.kind) for t in targets] == [
        ("203.0.113.1", 500, "ikev2")
    ]


def test_nordvpn_relays_without_ikev2_have_no_target():
    assert ikev2_targets(_relay("nordvpn", ("wireguard",))) == []


def test_pia_is_excluded_despite_publishing_an_ikev2_endpoint():
    """PIA answers IKE, but its listener is lossy exactly where its OpenVPN one
    is not — 0/3 to 3/3 with 1.5-2.3s outliers on seven regions where OpenVPN
    was 3/3. A two-second sample in a latency ranking is a fabricated answer."""
    assert ikev2_targets(_relay("pia", ("wireguard", "openvpn", "ikev2"))) == []


def test_providers_without_an_ikev2_fleet_have_no_target():
    assert ikev2_targets(_relay("airvpn", ("openvpn", "wireguard"))) == []
    assert ikev2_targets(_relay("mullvad", ("wireguard",))) == []
