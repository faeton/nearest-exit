from __future__ import annotations

from dataclasses import dataclass

from .models import Relay


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
