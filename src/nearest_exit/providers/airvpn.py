from __future__ import annotations

import asyncio
import json
import urllib.request
from typing import Any

from ..cache import JsonCache
from ..models import Relay

STATUS_URL = "https://airvpn.org/api/status/?format=json"
USER_AGENT = "nearest-exit/0.0.1"
CACHE_KEY = "airvpn-status"


def _http_get(url: str, timeout: float = 15.0) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
        return json.load(r)


def _entry_ips_v4(server: dict[str, Any]) -> list[str]:
    return [
        ip for ip in (server.get(f"ip_v4_in{i}") for i in (1, 2, 3, 4)) if ip
    ]


def _entry_ips_v6(server: dict[str, Any]) -> list[str]:
    return [
        ip for ip in (server.get(f"ip_v6_in{i}") for i in (1, 2, 3, 4)) if ip
    ]


def normalize(payload: dict[str, Any]) -> list[Relay]:
    """One Relay per AirVPN logical server.

    AirVPN exposes up to 4 IPv4 entry IPs per server. We use the first as the
    canonical probe target and preserve the rest under metadata['entry_ipv4_all']
    for V2 multi-target probing.
    """
    out: list[Relay] = []
    servers = payload.get("servers") or []
    for s in servers:
        ipv4s = _entry_ips_v4(s)
        ipv6s = _entry_ips_v6(s)
        if not ipv4s:
            continue
        load = s.get("currentload")
        health = (s.get("health") or "").lower()
        active = health == "ok"
        out.append(
            Relay(
                provider="airvpn",
                id=s.get("public_name") or ipv4s[0],
                hostname=s.get("public_name") or ipv4s[0],
                country_code=(s.get("country_code") or "").lower() or None,
                country_name=s.get("country_name"),
                city=s.get("location"),
                latitude=None,
                longitude=None,
                ipv4=ipv4s[0],
                ipv6=ipv6s[0] if ipv6s else None,
                protocols=("openvpn", "wireguard"),  # AirVPN supports both fleet-wide
                active=active,
                owned=None,
                load=float(load) if load is not None else None,
                metadata={
                    **s,
                    "entry_ipv4_all": ipv4s,
                    "entry_ipv6_all": ipv6s,
                    "health": health or None,
                },
            )
        )
    return out


class AirVPNProvider:
    name = "airvpn"

    async def fetch_relays(
        self, cache: JsonCache, refresh: bool = False
    ) -> list[Relay]:
        if not refresh and cache.fresh(CACHE_KEY):
            payload = cache.load(CACHE_KEY)
        else:
            payload = await asyncio.to_thread(_http_get, STATUS_URL)
            cache.save(CACHE_KEY, payload)
        return normalize(payload)
