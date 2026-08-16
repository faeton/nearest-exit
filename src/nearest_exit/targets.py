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


# Ports whose traffic is routinely intercepted on the way out by local DNS and
# NTP middleboxes. A probe sent to one of these measures the middlebox, not the
# relay — verified timing out or answering wrong from this side while the
# provider's other advertised ports answered correctly.
INTERCEPTED_PORTS = frozenset({53, 123})

# Used only if the payload carries no port list. PIA's advertised set is not
# stable: the live payload lists openvpn_udp on 8080/853/123/53 while an older
# captured one lists 53/1194/8080/9201, so the ports are read from the relay's
# own metadata rather than hardcoded, and this is the last resort.
PIA_OPENVPN_UDP_FALLBACK_PORTS = (8080, 1194)

# Probing every advertised port would multiply the packet count per relay for
# almost no information — they are the same daemon.
MAX_OPENVPN_UDP_TARGETS = 2

# Everyone else runs tls-auth/tls-crypt, so their UDP listeners stay silent to
# an unauthenticated reset. Over TCP they read it, fail the HMAC and close —
# still a daemon round trip. 443 is the port all three publish.
OPENVPN_TCP_PORT = 443


def _pia_openvpn_udp_ports(relay: Relay) -> list[int]:
    """Usable openvpn_udp ports from the relay's own payload, best first.

    Read rather than hardcoded because PIA changes the list: a captured payload
    advertises 53/1194/8080/9201 where the current one advertises
    8080/853/123/53.
    """
    groups = relay.metadata.get("groups")
    advertised: list[int] = []
    if isinstance(groups, dict):
        entries = groups.get("ovpnudp") or []
        if entries and isinstance(entries[0], dict):
            advertised = [int(p) for p in (entries[0].get("ports") or [])]
    usable = [p for p in advertised if p not in INTERCEPTED_PORTS]
    if not usable:
        usable = list(PIA_OPENVPN_UDP_FALLBACK_PORTS)
    return usable[:MAX_OPENVPN_UDP_TARGETS]


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
            ProbeTarget(str(ip), port, "openvpn-udp")
            for port in _pia_openvpn_udp_ports(relay)
        ]

    if relay.provider in ("airvpn", "nordvpn"):
        return [
            ProbeTarget(ip, OPENVPN_TCP_PORT, "openvpn-tcp")
            for ip in relay_entry_ips(relay)
        ]

    return []


IKEV2_UDP_PORT = 500


def ikev2_targets(relay: Relay) -> list[ProbeTarget]:
    """IKEv2 endpoints, which means NordVPN and nothing else.

    PIA publishes an `ikev2` service per region and answers on it, but its IKE
    listener is unreliable exactly where its OpenVPN one is not: on seven
    far-east and virtual regions the OpenVPN UDP probe answered 3/3 while IKE
    answered 0/3 to 3/3 with 1.5-2.3 second outliers. A two-second sample
    landing in a latency ranking is a fabricated answer that looks like a
    measurement, so PIA keeps the probe that works.

    AirVPN and Mullvad run no IKEv2 at all — OpenVPN and WireGuard, and
    WireGuard and bridges, respectively.
    """
    if relay.provider != "nordvpn":
        return []
    if "ikev2" not in {p.lower() for p in relay.protocols}:
        return []
    return [
        ProbeTarget(ip, IKEV2_UDP_PORT, "ikev2") for ip in relay_entry_ips(relay)
    ]


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
