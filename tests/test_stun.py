"""STUN parser unit tests. We don't open real sockets in CI."""
from nearest_exit.stun import (
    BINDING_SUCCESS,
    MAGIC_COOKIE,
    parse_response,
)


def _build_success_with_xor_mapped(public_ip_octets: tuple[int, int, int, int],
                                   port: int = 12345) -> bytes:
    cookie_bytes = MAGIC_COOKIE.to_bytes(4, "big")
    txid = b"\x00" * 12
    # XOR-MAPPED-ADDRESS: family=0x01 (IPv4)
    raw_addr = bytes(public_ip_octets)
    addr_int = int.from_bytes(raw_addr, "big")
    xaddr = (addr_int ^ MAGIC_COOKIE).to_bytes(4, "big")
    xport = (port ^ (MAGIC_COOKIE >> 16)).to_bytes(2, "big")
    attr_val = b"\x00\x01" + xport + xaddr  # reserved + family + xport + xaddr
    attr = (0x0020).to_bytes(2, "big") + len(attr_val).to_bytes(2, "big") + attr_val
    body = attr
    header = (
        BINDING_SUCCESS.to_bytes(2, "big")
        + len(body).to_bytes(2, "big")
        + cookie_bytes
        + txid
    )
    return header + body


def test_parse_xor_mapped_returns_public_ip():
    pkt = _build_success_with_xor_mapped((203, 0, 113, 42))
    assert parse_response(pkt) == "203.0.113.42"


def test_parse_rejects_short_packet():
    assert parse_response(b"\x00\x00") is None


def test_parse_rejects_non_success():
    pkt = b"\x01\x11" + b"\x00" * 18  # binding error response (0x0111)
    assert parse_response(pkt) is None
