"""Tiny STUN client for public-IP discovery (RFC 5389 binding request).

This is the smallest "no-HTTP" way for a NAT'd host to learn its public IP.
We send one UDP packet to a STUN server and parse XOR-MAPPED-ADDRESS from
the binding-success response. No body, no auth, no JSON, no third-party
service inspecting our request beyond UDP source-IP echo.
"""
from __future__ import annotations

import secrets
import socket

MAGIC_COOKIE = 0x2112A442
BINDING_REQUEST = 0x0001
BINDING_SUCCESS = 0x0101
ATTR_XOR_MAPPED_ADDRESS = 0x0020
ATTR_MAPPED_ADDRESS = 0x0001

DEFAULT_SERVERS = [
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
]


def _build_request(txid: bytes) -> bytes:
    return (
        BINDING_REQUEST.to_bytes(2, "big")
        + (0).to_bytes(2, "big")  # message length (no attrs)
        + MAGIC_COOKIE.to_bytes(4, "big")
        + txid
    )


def _parse_xor_mapped(attr_val: bytes) -> str | None:
    if len(attr_val) < 8 or attr_val[1] != 0x01:  # IPv4 only
        return None
    xport = int.from_bytes(attr_val[2:4], "big")
    xaddr = int.from_bytes(attr_val[4:8], "big")
    addr = xaddr ^ MAGIC_COOKIE
    _ = xport ^ (MAGIC_COOKIE >> 16)  # port not used
    return f"{(addr >> 24) & 0xFF}.{(addr >> 16) & 0xFF}.{(addr >> 8) & 0xFF}.{addr & 0xFF}"


def _parse_mapped(attr_val: bytes) -> str | None:
    if len(attr_val) < 8 or attr_val[1] != 0x01:
        return None
    return f"{attr_val[4]}.{attr_val[5]}.{attr_val[6]}.{attr_val[7]}"


def parse_response(data: bytes) -> str | None:
    if len(data) < 20:
        return None
    msg_type = int.from_bytes(data[0:2], "big")
    if msg_type != BINDING_SUCCESS:
        return None
    pos = 20
    while pos + 4 <= len(data):
        attr_type = int.from_bytes(data[pos:pos + 2], "big")
        attr_len = int.from_bytes(data[pos + 2:pos + 4], "big")
        attr_val = data[pos + 4:pos + 4 + attr_len]
        if attr_type == ATTR_XOR_MAPPED_ADDRESS:
            ip = _parse_xor_mapped(attr_val)
            if ip:
                return ip
        elif attr_type == ATTR_MAPPED_ADDRESS:
            ip = _parse_mapped(attr_val)
            if ip:
                return ip
        pos += 4 + ((attr_len + 3) & ~3)  # 4-byte aligned
    return None


def public_ip(server: str | None = None, port: int = 19302,
              timeout: float = 2.0) -> str | None:
    """Returns the host's public IPv4 string via STUN, or None on failure."""
    servers = [(server, port)] if server else DEFAULT_SERVERS
    for host, p in servers:
        try:
            txid = secrets.token_bytes(12)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(_build_request(txid), (host, p))
                data, _ = s.recvfrom(2048)
            ip = parse_response(data)
            if ip:
                return ip
        except (OSError, socket.timeout):
            continue
    return None
