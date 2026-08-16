from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from .models import Relay

# Addresses that are never a VPN relay on the public internet. A provider that
# publishes one of these is describing something reachable only from inside its
# own tunnel — Mullvad's SOCKS5 proxies live on 10.124.0.0/16 — and probing it
# from here would scan the user's own LAN instead. Deliberately narrower than
# `ipaddress.is_private`, which also covers the TEST-NET documentation ranges.
_UNROUTABLE = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
)


def is_probeable_address(host: str) -> bool:
    """False for addresses that cannot be a relay reachable from this machine.

    Hostnames pass: they are only known once resolved, and the check runs
    again on the resolved address.
    """
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return True
    if ip.version != 4:
        return not (ip.is_loopback or ip.is_link_local or ip.is_private)
    return not any(ip in net for net in _UNROUTABLE)


@dataclass(frozen=True)
class ProbeTarget:
    host: str
    port: int | None
    kind: str


def relay_entry_ips(relay: Relay) -> list[str]:
    ips = relay.metadata.get("entry_ipv4_all")
    if isinstance(ips, list):
        out = [str(ip) for ip in ips if ip]
        if out:
            return out
    return [relay.ipv4] if relay.ipv4 else []


def pia_service_target(relay: Relay, service: str) -> ProbeTarget | None:
    servers = relay.metadata.get("servers")
    groups = relay.metadata.get("groups")
    if not isinstance(servers, dict) or not isinstance(groups, dict):
        return None
    entries = servers.get(service) or []
    if not entries:
        return None
    ip = entries[0].get("ip")
    if not ip:
        return None
    ports = []
    group_entries = groups.get(service) or []
    if group_entries:
        ports = group_entries[0].get("ports") or []
    port = int(ports[0]) if ports else None
    kind = "socks5" if service == "socks5" else "tcp"
    return ProbeTarget(str(ip), port, kind)


def socks5_target(relay: Relay) -> ProbeTarget | None:
    if relay.provider == "pia":
        target = pia_service_target(relay, "socks5")
        if target and target.port:
            return target
    meta_target = relay.metadata.get("socks5_target")
    if isinstance(meta_target, dict):
        host = meta_target.get("host")
        port = meta_target.get("port")
        if host and port:
            return ProbeTarget(str(host), int(port), "socks5")
    return None


# PIA advertises openvpn_udp on 8080, 853, 123 and 53. The last two are
# routinely intercepted on the way out by local DNS and NTP middleboxes, so
# they measure the middlebox rather than the relay; verified timing out or
# answering wrong from this side while 8080 and 853 answered correctly.
PIA_OPENVPN_UDP_PORTS = (8080, 853)

# Everyone else runs tls-auth/tls-crypt, so their UDP listeners stay silent to
# an unauthenticated reset. Over TCP they read it, fail the HMAC and close —
# still a daemon round trip. 443 is the port all three publish.
OPENVPN_TCP_PORT = 443


def openvpn_targets(relay: Relay) -> list[ProbeTarget]:
    """Control-channel endpoints for measuring the OpenVPN daemon itself.

    Mullvad returns nothing: it has no OpenVPN fleet, its relays are WireGuard
    or bridges only.
    """
    if relay.provider == "pia":
        servers = relay.metadata.get("servers")
        if not isinstance(servers, dict):
            return []
        entries = servers.get("ovpnudp") or []
        ip = entries[0].get("ip") if entries else None
        if not ip:
            return []
        return [
            ProbeTarget(str(ip), port, "openvpn-udp") for port in PIA_OPENVPN_UDP_PORTS
        ]

    if relay.provider in ("airvpn", "nordvpn"):
        return [
            ProbeTarget(ip, OPENVPN_TCP_PORT, "openvpn-tcp")
            for ip in relay_entry_ips(relay)
        ]

    return []


def tcp_fallback_targets(relay: Relay, feature: str | None = None) -> list[ProbeTarget]:
    if feature == "socks5":
        target = socks5_target(relay)
        return [target] if target else []

    if relay.provider == "pia":
        if feature == "openvpn":
            target = pia_service_target(relay, "ovpntcp")
            if target and target.port:
                return [target]
        target = pia_service_target(relay, "meta")
        if target and target.port:
            return [target]

    return [ProbeTarget(ip, 443, "tcp") for ip in relay_entry_ips(relay)]
