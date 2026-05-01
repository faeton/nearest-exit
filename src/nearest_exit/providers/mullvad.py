from __future__ import annotations

import asyncio
import urllib.request
from typing import Any

from ..cache import JsonCache
from ..models import Relay

API_URL = "https://api.mullvad.net/www/relays/all/"
CACHE_KEY = "mullvad-relays"


def _fetch_sync(timeout: float = 15.0) -> list[dict[str, Any]]:
    with urllib.request.urlopen(API_URL, timeout=timeout) as r:  # noqa: S310
        return list(__import__("json").load(r))


def normalize(raw: list[dict[str, Any]]) -> list[Relay]:
    out: list[Relay] = []
    for h in raw:
        protocols: tuple[str, ...] = ()
        t = (h.get("type") or "").lower()
        if t:
            protocols = (t,)
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
                protocols=protocols,
                active=h.get("active"),
                owned=h.get("owned"),
                load=None,
                metadata=h,
            )
        )
    return out


class MullvadProvider:
    name = "mullvad"

    async def fetch_relays(
        self, cache: JsonCache, refresh: bool = False
    ) -> list[Relay]:
        if not refresh and cache.fresh(CACHE_KEY):
            raw = cache.load(CACHE_KEY)
        else:
            raw = await asyncio.to_thread(_fetch_sync)
            cache.save(CACHE_KEY, raw)
        return normalize(raw)
