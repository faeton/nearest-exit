from __future__ import annotations

import asyncio
import json
import urllib.request
from typing import Any

from ..cache import JsonCache
from ..models import Relay

SERVERS_URL = "https://serverlist.piaservers.net/vpninfo/servers/v6"
USER_AGENT = "nearest-exit/0.0.1"
CACHE_KEY = "pia-servers-v6"


def _http_get_text(url: str, timeout: float = 15.0) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
        return r.read().decode("utf-8", errors="replace")


def parse_payload(text: str) -> dict[str, Any]:
    """PIA returns one JSON object followed by a newline and a base64 signature.

    Use raw_decode to consume only the first JSON value and ignore the tail.
    """
    obj, _idx = json.JSONDecoder().raw_decode(text.lstrip())
    if not isinstance(obj, dict):
        raise ValueError("PIA payload is not a JSON object")
    return obj


_PROTO_MAP = {
    "wg": "wireguard",
    "ovpnudp": "openvpn",
    "ovpntcp": "openvpn",
    "socks5": "socks5",
    # "meta" is a control endpoint, not a tunnel — skip from protocols.
}


def _pick_canonical_target(servers: dict[str, Any]) -> tuple[str | None, str | None]:
    """Return (ipv4, service_key) preferring wireguard, then openvpn-udp."""
    for key in ("wg", "ovpnudp", "ovpntcp", "socks5"):
        entries = servers.get(key) or []
        if entries:
            ip = entries[0].get("ip")
            if ip:
                return ip, key
    return None, None


def normalize(payload: dict[str, Any]) -> list[Relay]:
    """One Relay per PIA region.

    The region's wireguard endpoint (if present) is the canonical probe IP.
    All per-protocol IPs are preserved under metadata['servers'].
    """
    groups = payload.get("groups") or {}
    out: list[Relay] = []
    for region in payload.get("regions") or []:
        servers = region.get("servers") or {}
        ip, _which = _pick_canonical_target(servers)
        if not ip:
            continue
        protocols = tuple(
            sorted({_PROTO_MAP[k] for k in servers.keys() if k in _PROTO_MAP})
        )
        cc_raw = region.get("country") or ""
        offline = bool(region.get("offline"))
        active = not offline
        out.append(
            Relay(
                provider="pia",
                id=str(region.get("id") or region.get("dns") or ip),
                hostname=region.get("dns") or str(region.get("id") or ip),
                country_code=cc_raw.lower() or None,
                country_name=None,
                city=region.get("name"),
                latitude=None,
                longitude=None,
                ipv4=ip,
                ipv6=None,
                protocols=protocols,
                active=active,
                owned=None,
                load=None,
                metadata={
                    "id": region.get("id"),
                    "name": region.get("name"),
                    "country": cc_raw,
                    "dns": region.get("dns"),
                    "port_forward": bool(region.get("port_forward")),
                    "geo": bool(region.get("geo")),
                    "offline": offline,
                    "auto_region": bool(region.get("auto_region")),
                    "servers": servers,
                    "groups": groups,
                },
            )
        )
    return out


class PIAProvider:
    name = "pia"

    async def fetch_relays(
        self, cache: JsonCache, refresh: bool = False
    ) -> list[Relay]:
        if not refresh and cache.fresh(CACHE_KEY):
            payload = cache.load(CACHE_KEY)
        else:
            text = await asyncio.to_thread(_http_get_text, SERVERS_URL)
            payload = parse_payload(text)
            cache.save(CACHE_KEY, payload)
        return normalize(payload)
