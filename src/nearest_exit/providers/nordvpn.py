from __future__ import annotations

import asyncio
import json
import urllib.parse
import urllib.request
from typing import Any

from ..cache import JsonCache
from ..models import Relay

REC_URL = "https://api.nordvpn.com/v1/servers/recommendations"
COUNTRIES_URL = "https://api.nordvpn.com/v1/servers/countries"
DEFAULT_LIMIT = 50
USER_AGENT = "nearest-exit/0.0.1"

CACHE_KEY_REC = "nordvpn-recommendations"
CACHE_KEY_COUNTRIES = "nordvpn-countries"


def _http_get(url: str, timeout: float = 15.0) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
        return json.load(r)


def _build_rec_url(
    limit: int,
    country_id: int | None = None,
    technology: str | None = None,
) -> str:
    params: list[tuple[str, str]] = [("limit", str(limit))]
    if country_id is not None:
        params.append(("filters[country_id]", str(country_id)))
    if technology:
        params.append(("filters[servers_technologies][identifier]", technology))
    return f"{REC_URL}?{urllib.parse.urlencode(params)}"


def normalize(raw: list[dict[str, Any]]) -> list[Relay]:
    out: list[Relay] = []
    for s in raw:
        loc = (s.get("locations") or [{}])[0]
        country = loc.get("country") or {}
        city = (country.get("city") or {}) if isinstance(country, dict) else {}

        seen: set[str] = set()
        for tech in s.get("technologies") or []:
            ident = tech.get("identifier")
            if not ident:
                continue
            if ident == "wireguard_udp":
                seen.add("wireguard")
            elif ident in ("openvpn_udp", "openvpn_tcp"):
                seen.add("openvpn")
            elif ident == "ikev2":
                seen.add("ikev2")
        # Display preference: WireGuard > OpenVPN > IKEv2.
        protocols = [p for p in ("wireguard", "openvpn", "ikev2") if p in seen]

        ipv4 = s.get("station") or None
        if not ipv4:
            ips = s.get("ips") or []
            for entry in ips:
                ip = (entry.get("ip") or {}).get("ip")
                if ip and (entry.get("ip") or {}).get("version") == 4:
                    ipv4 = ip
                    break

        load = s.get("load")
        active = (s.get("status") == "online") if s.get("status") is not None else None

        out.append(
            Relay(
                provider="nordvpn",
                id=str(s.get("id") or s.get("hostname") or s.get("name")),
                hostname=s.get("hostname") or s.get("name") or "",
                country_code=(country.get("code") or "").lower() or None,
                country_name=country.get("name"),
                city=city.get("name") if isinstance(city, dict) else None,
                latitude=loc.get("latitude"),
                longitude=loc.get("longitude"),
                ipv4=ipv4,
                ipv6=s.get("ipv6_station") or None,
                protocols=tuple(protocols),
                active=active,
                owned=None,
                load=float(load) if load is not None else None,
                metadata=s,
            )
        )
    return out


class NordVPNProvider:
    name = "nordvpn"

    def __init__(
        self,
        country_id: int | None = None,
        technology: str | None = None,
        limit: int = DEFAULT_LIMIT,
    ):
        self.country_id = country_id
        self.technology = technology
        self.limit = limit

    async def fetch_relays(
        self, cache: JsonCache, refresh: bool = False
    ) -> list[Relay]:
        cache_key = (
            f"{CACHE_KEY_REC}-l{self.limit}"
            f"-c{self.country_id or 'any'}-t{self.technology or 'any'}"
        )
        if not refresh and cache.fresh(cache_key):
            raw = cache.load(cache_key)
        else:
            url = _build_rec_url(self.limit, self.country_id, self.technology)
            raw = await asyncio.to_thread(_http_get, url)
            cache.save(cache_key, raw)
        return normalize(raw)


async def fetch_countries(cache: JsonCache, refresh: bool = False) -> list[dict[str, Any]]:
    if not refresh and cache.fresh(CACHE_KEY_COUNTRIES):
        return cache.load(CACHE_KEY_COUNTRIES)
    data = await asyncio.to_thread(_http_get, COUNTRIES_URL)
    cache.save(CACHE_KEY_COUNTRIES, data)
    return data


def country_code_to_id(countries: list[dict[str, Any]], code: str) -> int | None:
    code_upper = code.upper()
    for c in countries:
        if (c.get("code") or "").upper() == code_upper:
            return c.get("id")
    name_lower = code.lower()
    for c in countries:
        if (c.get("name") or "").lower() == name_lower:
            return c.get("id")
    return None
