from __future__ import annotations

import asyncio
import json
import urllib.request
from typing import Any

from ..cache import JsonCache
from ..models import Relay

API_URL = "https://api.mullvad.net/www/relays/all/"
CACHE_KEY = "mullvad-relays"


def _fetch_sync(timeout: float = 15.0) -> list[dict[str, Any]]:
    with urllib.request.urlopen(API_URL, timeout=timeout) as r:  # noqa: S310
        return list(json.load(r))


def _socks5_target(h: dict[str, Any]) -> dict[str, Any] | None:
    """Mullvad publishes a SOCKS5 endpoint per relay; 574 of 587 have one.

    `targets.socks5_target` reads this shape, so normalizing it here is all
    that was needed to make `--protocol socks5` work outside PIA.
    """
    host = h.get("socks_name")
    port = h.get("socks_port")
    if not host or not port:
        return None
    return {"host": str(host), "port": int(port)}


def normalize(raw: list[dict[str, Any]]) -> list[Relay]:
    out: list[Relay] = []
    for h in raw:
        protocols: list[str] = []
        t = (h.get("type") or "").lower()
        if t:
            protocols.append(t)
        socks = _socks5_target(h)
        if socks:
            protocols.append("socks5")
        metadata: dict[str, Any] = dict(h)
        if socks:
            metadata["socks5_target"] = socks
        out.append(
            Relay(
                provider="mullvad",
                id=h["hostname"],
                hostname=h["hostname"],
                country_code=h.get("country_code"),
                country_name=h.get("country_name"),
                city=h.get("city_name") or h.get("city_code"),
                latitude=h.get("latitude"),
                longitude=h.get("longitude"),
                ipv4=h.get("ipv4_addr_in"),
                ipv6=h.get("ipv6_addr_in"),
                protocols=tuple(protocols),
                active=h.get("active"),
                owned=h.get("owned"),
                load=None,
                metadata=metadata,
            )
        )
    return out


class MullvadProvider:
    name = "mullvad"

    async def fetch_relays(
        self, cache: JsonCache, refresh: bool = False
    ) -> list[Relay]:
        raw = cache.load(CACHE_KEY) if not refresh and cache.fresh(CACHE_KEY) else None
        if raw is None:
            raw = await asyncio.to_thread(_fetch_sync)
            cache.save(CACHE_KEY, raw)
        return normalize(raw)
