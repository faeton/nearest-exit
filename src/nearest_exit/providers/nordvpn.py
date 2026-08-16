from __future__ import annotations

import asyncio
import json
import sys
import urllib.parse
import urllib.request
from dataclasses import replace
from typing import Any

from ..cache import JsonCache
from ..countries import country_centroid
from ..models import GEO_PRECISION_CITY, GEO_PRECISION_COUNTRY, Relay

# /v1/servers is NordVPN's raw inventory; /v1/servers/recommendations is NordVPN's
# own ranking of it. This tool exists to rank servers independently, so the
# inventory endpoint is the candidate source and recommendations is only a fallback.
SERVERS_URL = "https://api.nordvpn.com/v1/servers"
REC_URL = "https://api.nordvpn.com/v1/servers/recommendations"
COUNTRIES_URL = "https://api.nordvpn.com/v1/servers/countries"

DEFAULT_LIMIT = 50
# NordVPN treats limit=0 as "no limit" (~8.8k servers).
FULL_INVENTORY = 0
# Even the sparse fetch is a few megabytes over one connection, so it needs more
# headroom than the small country/recommendation calls.
INVENTORY_TIMEOUT = 90.0
USER_AGENT = "nearest-exit/0.0.1"

# Sparse fieldsets. The array spelling `fields[]=id` is rejected with HTTP 400
# {"errors":{"message":"Invalid request","code":200138}}, but the dotted key
# spelling `fields[servers.<path>]` — the form NordVPN's own Linux client uses —
# is honoured, nested paths included. That takes the full limit=0 fetch from
# 33.4 MB to 4.6 MB, so no structural client-side trimming is needed.
#
# The API drops unknown paths silently instead of erroring, so this tuple is the
# contract: anything normalize() or spread() reads must be listed here or it
# arrives as None. `station` is populated for every inventory server, so the
# `ips[]` fallback in normalize() (which only the recommendations payload needs)
# is deliberately not requested.
INVENTORY_FIELDS = (
    "servers.id",
    "servers.name",
    "servers.hostname",
    "servers.station",
    "servers.ipv6_station",
    "servers.load",
    "servers.status",
    "servers.locations.latitude",
    "servers.locations.longitude",
    "servers.locations.country.code",
    "servers.locations.country.name",
    "servers.locations.country.city.name",
    "servers.technologies.identifier",
)

CACHE_KEY_REC = "nordvpn-recommendations"
# v3 marks the sparse-fieldset inventory shape; bumping the key stops caches in
# any earlier format from being read back as if they were this one.
CACHE_KEY_INVENTORY = "nordvpn-inventory-v3"
CACHE_KEY_COUNTRIES = "nordvpn-countries"

SOURCE_INVENTORY = "inventory"
SOURCE_RECOMMENDATIONS = "recommendations"
# Stamped into Relay.metadata so a degraded (recommendation-sourced) run is
# visible downstream instead of passing as a full inventory scan.
SOURCE_FIELD = "_nearest_exit_source"
# Size of the inventory before spread() reduced it, so callers can report how
# much of the fleet was never a candidate.
FLEET_SIZE_FIELD = "_nearest_exit_fleet_size"

# Only the transport protocols normalize() maps; the rest (proxies, NordWhisper,
# obfuscated and dedicated-IP variants) are dead weight. `fields` selects keys,
# not values, and `filters[servers_technologies][identifier]` picks servers
# rather than pruning their technologies list, so this one filter cannot be
# pushed to the server: it saves ~1.2 MB of cache and Relay.metadata.
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
    """Inventory URL. limit=0 asks the API for every server it knows about.

    Carries the sparse fieldset so the response is only the ~14% of each server
    object this tool actually reads.
    """
    params = [("limit", str(limit))] + _filter_params(country_id, technology)
    params += [(f"fields[{path}]", "") for path in INVENTORY_FIELDS]
    return f"{SERVERS_URL}?{urllib.parse.urlencode(params)}"


def _build_rec_url(
    limit: int,
    country_id: int | None = None,
    technology: str | None = None,
) -> str:
    params = [("limit", str(limit))] + _filter_params(country_id, technology)
    return f"{REC_URL}?{urllib.parse.urlencode(params)}"


def prune_inventory(raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop technology entries normalize() cannot map, and servers left with none.

    The sparse fieldset already removes every *key* this tool ignores; the only
    thing left to trim is *values*, which `fields` cannot express. Servers
    advertise ~8 technologies each and normalize() maps 4 of them.

    A server whose whole technology list falls outside that set — the SOCKS
    proxies and the XOR-obfuscated OpenVPN relays, ~170 of ~8.8k — cannot serve
    as an exit here at all, so probing it would burn a candidate slot on
    something unusable. This is a capability filter, not a quality one: it asks
    what a server *can* do, never how good NordVPN thinks it is.
    """
    out: list[dict[str, Any]] = []
    for server in raw:
        techs = server.get("technologies")
        if not isinstance(techs, list):
            out.append(server)
            continue
        kept = [
            t for t in techs
            if isinstance(t, dict) and t.get("identifier") in _KEPT_TECHNOLOGIES
        ]
        if not kept:
            continue
        out.append(server | {"technologies": kept})
    return out


def _group_key(server: dict[str, Any]) -> tuple[str, str]:
    loc = (server.get("locations") or [{}])[0]
    country = loc.get("country") or {}
    if not isinstance(country, dict):
        country = {}
    city = country.get("city") or {}
    city_name = city.get("name") if isinstance(city, dict) else None
    return ((country.get("code") or "").upper(), city_name or "")


def _rank_key(server: dict[str, Any]) -> tuple[str, str]:
    """Neutral within-bucket order: hostname, then id as a tiebreaker.

    Deliberately ignores `load`. Sorting by NordVPN's reported load would let the
    provider decide which servers ever get measured — the least-loaded relay in
    each city would be the only one probed, so a busy relay with better peering
    could never become a candidate. That is a self-fulfilling filter and exactly
    the provider judgement this tool exists to route around. `load` still reaches
    Relay.load and is reported in the output, but it is not ranked on either.
    """
    return (str(server.get("hostname") or ""), str(server.get("id") or ""))


def spread(servers: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    """Pick `limit` servers spread evenly across cities.

    The inventory comes back ordered by server id, which clusters by country, so
    a plain head() of 50 would return one country's block and never surface the
    rest. Round-robin over (country, city) buckets keeps the candidate set wide;
    within a bucket servers are ordered by _rank_key, which is deliberately
    independent of any provider quality signal. Bucket order follows the API's
    order, so the selection is deterministic and cache friendly.
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

        cc = (country.get("code") or "").lower() or None
        city_name = city.get("name") if isinstance(city, dict) else None
        # NordVPN is the only provider that returns coordinates, but they are
        # per-city, not per-machine: across 800 sampled servers in 30 cities
        # there is exactly one coordinate per city, and London and Paris match
        # Mullvad's independently published city table byte for byte. Label
        # them for what they are.
        lat, lon = loc.get("latitude"), loc.get("longitude")
        precision = GEO_PRECISION_CITY if lat is not None and lon is not None else None
        if precision is None and cc:
            centroid = country_centroid(cc)
            if centroid:
                lat, lon = centroid
                precision = GEO_PRECISION_COUNTRY
        metadata["geo_precision"] = precision

        out.append(
            Relay(
                provider="nordvpn",
                id=str(s.get("id") or s.get("hostname") or s.get("name")),
                hostname=s.get("hostname") or s.get("name") or "",
                country_code=cc,
                country_name=country.get("name"),
                city=city_name,
                latitude=lat,
                longitude=lon,
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
                raw = prune_inventory(full)
            except Exception as exc:  # network, timeout, or malformed payload
                if not self.allow_recommendation_fallback:
                    raise
                self.fallback_reason = f"{type(exc).__name__}: {exc}"
                return await self._fetch_recommendations(cache, refresh)
            cache.save(key, raw)

        self.source = SOURCE_INVENTORY
        self.fallback_reason = None
        relays = normalize(spread(raw, self.limit), source=SOURCE_INVENTORY)
        # The caller only sees the spread subset, so without this it would
        # report "60 of 500 probed" and make a sample of ~8600 look like the
        # whole fleet. Stamp the real size so the frame stays honest.
        return [
            replace(r, metadata={**r.metadata, FLEET_SIZE_FIELD: len(raw)})
            for r in relays
        ]

    async def _fetch_recommendations(
        self, cache: JsonCache, refresh: bool
    ) -> list[Relay]:
        """Degraded path: NordVPN's own ranking, tagged so callers can tell.

        The metadata stamp and the `source`/`fallback_reason` attributes only help
        callers that inspect the provider object, and none currently do — so the
        warning goes straight to stderr, where a degraded run cannot be mistaken
        for a full independent scan no matter who invoked it.
        """
        self.source = SOURCE_RECOMMENDATIONS
        print(
            f"WARNING: nordvpn: inventory fetch failed ({self.fallback_reason}); "
            f"falling back to {REC_URL} — candidates are NordVPN's own ranking, "
            f"not an independent scan of the full inventory.",
            file=sys.stderr,
        )
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
