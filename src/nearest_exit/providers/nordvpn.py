from __future__ import annotations

import asyncio
import json
import urllib.parse
import urllib.request
from typing import Any

from ..cache import JsonCache
from ..models import Relay

# /v1/servers is NordVPN's raw inventory; /v1/servers/recommendations is NordVPN's
# own ranking of it. This tool exists to rank servers independently, so the
# inventory endpoint is the candidate source and recommendations is only a fallback.
SERVERS_URL = "https://api.nordvpn.com/v1/servers"
REC_URL = "https://api.nordvpn.com/v1/servers/recommendations"
COUNTRIES_URL = "https://api.nordvpn.com/v1/servers/countries"

DEFAULT_LIMIT = 50
# NordVPN treats limit=0 as "no limit" (~8.8k servers, ~33 MB raw).
FULL_INVENTORY = 0
# The full fetch is a multi-second, tens-of-megabytes transfer, so it needs more
# headroom than the small country/recommendation calls.
INVENTORY_TIMEOUT = 90.0
USER_AGENT = "nearest-exit/0.0.1"

CACHE_KEY_REC = "nordvpn-recommendations"
# v2 marks the trimmed inventory shape written by _slim(); bumping the key stops
# caches from any earlier format being read back as if they were this one.
CACHE_KEY_INVENTORY = "nordvpn-inventory-v2"
CACHE_KEY_COUNTRIES = "nordvpn-countries"

SOURCE_INVENTORY = "inventory"
SOURCE_RECOMMENDATIONS = "recommendations"
# Stamped into Relay.metadata so a degraded (recommendation-sourced) run is
# visible downstream instead of passing as a full inventory scan.
SOURCE_FIELD = "_nearest_exit_source"

# Only the transport protocols normalize() maps; the rest (proxies, NordWhisper,
# obfuscated variants) are dead weight in a 33 MB payload.
_KEPT_TECHNOLOGIES = frozenset(
    {"wireguard_udp", "openvpn_udp", "openvpn_tcp", "ikev2"}
)


def _http_get(url: str, timeout: float = 15.0) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
        return json.load(r)


def _filter_params(
    country_id: int | None = None,
    technology: str | None = None,
) -> list[tuple[str, str]]:
    params: list[tuple[str, str]] = []
    if country_id is not None:
        params.append(("filters[country_id]", str(country_id)))
    if technology:
        params.append(("filters[servers_technologies][identifier]", technology))
    return params


def _build_servers_url(
    limit: int = FULL_INVENTORY,
    country_id: int | None = None,
    technology: str | None = None,
) -> str:
    """Inventory URL. limit=0 asks the API for every server it knows about."""
    params = [("limit", str(limit))] + _filter_params(country_id, technology)
    return f"{SERVERS_URL}?{urllib.parse.urlencode(params)}"


def _build_rec_url(
    limit: int,
    country_id: int | None = None,
    technology: str | None = None,
) -> str:
    params = [("limit", str(limit))] + _filter_params(country_id, technology)
    return f"{REC_URL}?{urllib.parse.urlencode(params)}"


def _slim(server: dict[str, Any]) -> dict[str, Any]:
    """Drop everything normalize() does not read.

    The API has no sparse-fieldset support (any `fields` parameter 400s), so
    trimming has to happen client side. This is what makes the cached inventory
    ~4 MB instead of ~33 MB.
    """
    loc = (server.get("locations") or [{}])[0]
    country = loc.get("country") or {}
    if not isinstance(country, dict):
        country = {}
    city = country.get("city") or {}
    if not isinstance(city, dict):
        city = {}

    slim_country: dict[str, Any] = {
        "id": country.get("id"),
        "code": country.get("code"),
        "name": country.get("name"),
    }
    if city:
        slim_country["city"] = {"name": city.get("name")}

    return {
        "id": server.get("id"),
        "name": server.get("name"),
        "hostname": server.get("hostname"),
        "station": server.get("station"),
        "ipv6_station": server.get("ipv6_station"),
        "load": server.get("load"),
        "status": server.get("status"),
        "locations": [
            {
                "latitude": loc.get("latitude"),
                "longitude": loc.get("longitude"),
                "country": slim_country,
            }
        ],
        "technologies": [
            {"identifier": t.get("identifier")}
            for t in server.get("technologies") or []
            if t.get("identifier") in _KEPT_TECHNOLOGIES
        ],
    }


def slim_inventory(raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [_slim(s) for s in raw]


def _group_key(server: dict[str, Any]) -> tuple[str, str]:
    loc = (server.get("locations") or [{}])[0]
    country = loc.get("country") or {}
    if not isinstance(country, dict):
        country = {}
    city = country.get("city") or {}
    city_name = city.get("name") if isinstance(city, dict) else None
    return ((country.get("code") or "").upper(), city_name or "")


def _rank_key(server: dict[str, Any]) -> tuple[float, str]:
    load = server.get("load")
    return (float(load) if load is not None else 100.0, str(server.get("hostname") or ""))


def spread(servers: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    """Pick `limit` servers spread evenly across cities.

    The inventory comes back ordered by server id, which clusters by country, so
    a plain head() of 50 would return one country's block and never surface the
    rest. Round-robin over (country, city) buckets keeps the candidate set wide;
    within a bucket the least loaded server goes first. Bucket order follows the
    API's order, so the selection is deterministic and cache friendly.
    """
    if limit <= 0 or limit >= len(servers):
        return list(servers)

    buckets: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for s in servers:
        buckets.setdefault(_group_key(s), []).append(s)
    ordered = list(buckets.values())
    for bucket in ordered:
        bucket.sort(key=_rank_key)

    out: list[dict[str, Any]] = []
    depth = 0
    while len(out) < limit:
        progressed = False
        for bucket in ordered:
            if depth >= len(bucket):
                continue
            out.append(bucket[depth])
            progressed = True
            if len(out) >= limit:
                break
        if not progressed:
            break
        depth += 1
    return out


def normalize(raw: list[dict[str, Any]], source: str | None = None) -> list[Relay]:
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

        metadata: dict[str, Any] = dict(s)
        if source:
            metadata[SOURCE_FIELD] = source

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
                metadata=metadata,
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
        allow_recommendation_fallback: bool = True,
    ):
        self.country_id = country_id
        self.technology = technology
        self.limit = limit
        self.allow_recommendation_fallback = allow_recommendation_fallback
        # Set by fetch_relays; SOURCE_RECOMMENDATIONS means the run saw only
        # NordVPN's own shortlist, not the full inventory.
        self.source: str | None = None
        self.fallback_reason: str | None = None

    def _inventory_cache_key(self) -> str:
        return (
            f"{CACHE_KEY_INVENTORY}"
            f"-c{self.country_id or 'any'}-t{self.technology or 'any'}"
        )

    def _rec_cache_key(self) -> str:
        return (
            f"{CACHE_KEY_REC}-l{self.limit}"
            f"-c{self.country_id or 'any'}-t{self.technology or 'any'}"
        )

    async def fetch_relays(
        self, cache: JsonCache, refresh: bool = False
    ) -> list[Relay]:
        key = self._inventory_cache_key()
        raw: list[dict[str, Any]] | None = None
        if not refresh and cache.fresh(key):
            raw = cache.load(key)

        if raw is None:
            url = _build_servers_url(
                FULL_INVENTORY, self.country_id, self.technology
            )
            try:
                full = await asyncio.to_thread(_http_get, url, INVENTORY_TIMEOUT)
                raw = slim_inventory(full)
            except Exception as exc:  # network, timeout, or malformed payload
                if not self.allow_recommendation_fallback:
                    raise
                self.fallback_reason = f"{type(exc).__name__}: {exc}"
                return await self._fetch_recommendations(cache, refresh)
            cache.save(key, raw)

        self.source = SOURCE_INVENTORY
        self.fallback_reason = None
        return normalize(spread(raw, self.limit), source=SOURCE_INVENTORY)

    async def _fetch_recommendations(
        self, cache: JsonCache, refresh: bool
    ) -> list[Relay]:
        """Degraded path: NordVPN's own ranking, tagged so callers can tell."""
        self.source = SOURCE_RECOMMENDATIONS
        key = self._rec_cache_key()
        raw = cache.load(key) if not refresh and cache.fresh(key) else None
        if raw is None:
            url = _build_rec_url(self.limit, self.country_id, self.technology)
            raw = await asyncio.to_thread(_http_get, url)
            cache.save(key, raw)
        return normalize(raw, source=SOURCE_RECOMMENDATIONS)


async def fetch_countries(cache: JsonCache, refresh: bool = False) -> list[dict[str, Any]]:
    cached = (
        cache.load(CACHE_KEY_COUNTRIES)
        if not refresh and cache.fresh(CACHE_KEY_COUNTRIES) else None
    )
    if cached is not None:
        return cached
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
