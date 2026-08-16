from __future__ import annotations

import asyncio
import json
import urllib.request
from typing import Any

from ..cache import JsonCache
from ..cities import city_coords
from ..countries import country_centroid
from ..models import GEO_PRECISION_CITY, GEO_PRECISION_COUNTRY, Relay

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
    """One Relay per Mullvad server.

    `/www/relays/all/` publishes no coordinates — only country_code and
    city_name — so position comes from the embedded city table, which was
    itself built from Mullvad's own `/app/v1/relays` location list and
    therefore covers every city Mullvad serves.
    """
    out: list[Relay] = []
    for h in raw:
        protocols: list[str] = []
        t = (h.get("type") or "").lower()
        if t:
            protocols.append(t)
        socks = _socks5_target(h)
        if socks:
            protocols.append("socks5")
        cc = h.get("country_code")
        city = h.get("city_name") or h.get("city_code")
        coords = city_coords(cc, city)
        precision = GEO_PRECISION_CITY if coords else None
        if coords is None and cc:
            coords = country_centroid(cc)
            precision = GEO_PRECISION_COUNTRY if coords else None
        metadata: dict[str, Any] = dict(h)
        if socks:
            metadata["socks5_target"] = socks
        metadata["geo_precision"] = precision
        out.append(
            Relay(
                provider="mullvad",
                id=h["hostname"],
                hostname=h["hostname"],
                country_code=cc,
                country_name=h.get("country_name"),
                city=city,
                latitude=coords[0] if coords else None,
                longitude=coords[1] if coords else None,
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
