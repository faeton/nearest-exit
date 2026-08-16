from __future__ import annotations

import asyncio
import json
import urllib.request
from typing import Any

from ..cache import JsonCache
from ..cities import GEO_PRECISION_CITY, city_coords
from ..countries import GEO_PRECISION_COUNTRY, country_centroid
from ..models import GEO_PRECISION_REGION, Relay
from ..subdivisions import subdivision_coords

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


def _region_city(name: str | None, cc: str | None) -> str | None:
    """Strip PIA's country tag off a region name: "DE Berlin" and "UK London"
    denote cities, "Netherlands" and "US East" do not. Untagged names are
    returned unchanged; whether what remains names a city is the city table's
    call, not ours."""
    if not name:
        return None
    label = name.strip()
    tag, sep, rest = label.partition(" ")
    if not sep or not rest.strip() or not cc:
        return label or None
    tags = {cc.upper()}
    if cc.upper() == "GB":
        tags.add("UK")  # PIA labels its British regions "UK ...".
    return rest.strip() if tag.upper() in tags else label


def _id_city(region_id: Any, cc: str | None) -> str | None:
    """PIA's region ids are slugs that often name the city the label hides
    ("Netherlands" is nl_amsterdam, "Bulgaria" is sofia). Turn one into a
    lookup candidate; a slug that names no city simply misses the table."""
    slug = str(region_id or "").strip().lower()
    for suffix in ("-pf", "-so"):
        if slug.endswith(suffix):
            slug = slug[: -len(suffix)]
    tokens = slug.replace("_", " ").replace("-", " ").split()
    if cc and tokens and tokens[0] == cc.lower():
        tokens = tokens[1:]
    return " ".join(tokens) or None


def _region_coords(region: dict[str, Any], cc: str | None) -> tuple[float, float] | None:
    """City coordinates for a region, from its label first and its id second."""
    for candidate in (_region_city(region.get("name"), cc), _id_city(region.get("id"), cc)):
        coords = city_coords(cc, candidate)
        if coords is not None:
            return coords
    return None


def _city_label(region: dict[str, Any], cc: str | None) -> str | None:
    """What to call this region's city.

    PIA tags region names with a country ("DE Berlin", "UK London"), so the
    stored city used to be `DE Berlin` while `--city Berlin` matched exactly.
    PIA relays were therefore invisible to a city filter that worked for every
    other provider, and the label disagreed with the coordinates, which were
    already looked up under the stripped name.

    Only strip when the remainder names a city the table actually knows. That
    keeps labels like "US East" — which is a region, not a city — from being
    shortened to a meaningless "East".
    """
    name = region.get("name")
    stripped = _region_city(name, cc)
    if stripped and stripped != name and city_coords(cc, stripped) is not None:
        return stripped
    return name


def _region_subdivision(region: dict[str, Any], cc: str | None) -> tuple[float, float] | None:
    """State/province coordinates for a region, from its label first and its id
    second. The id is worth trying because it survives PIA's marketing suffixes:
    "CA Ontario Streaming Optimized" is still ca_ontario-so."""
    for candidate in (region.get("name"), _id_city(region.get("id"), cc)):
        coords = subdivision_coords(cc, candidate)
        if coords is not None:
            return coords
    return None


def normalize(payload: dict[str, Any]) -> list[Relay]:
    """One Relay per PIA region.

    The region's wireguard endpoint (if present) is the canonical probe IP.
    All per-protocol IPs are preserved under metadata['servers'].

    The server list carries no coordinates (only an ISO-2 country plus a
    city-ish label and id), so coordinates are back-filled from the embedded
    city table, then the subdivision table — most of PIA's US regions name a
    state and nothing finer — then the country centroid, and the source is
    recorded in metadata['geo_precision'].
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
        cc = cc_raw.lower() or None
        coords = _region_coords(region, cc)
        precision = GEO_PRECISION_CITY if coords else None
        if coords is None:
            coords = _region_subdivision(region, cc)
            precision = GEO_PRECISION_REGION if coords else None
        if coords is None and cc:
            coords = country_centroid(cc)
            precision = GEO_PRECISION_COUNTRY if coords else None
        offline = bool(region.get("offline"))
        active = not offline
        out.append(
            Relay(
                provider="pia",
                id=str(region.get("id") or region.get("dns") or ip),
                hostname=region.get("dns") or str(region.get("id") or ip),
                country_code=cc,
                country_name=None,
                city=_city_label(region, cc),
                latitude=coords[0] if coords else None,
                longitude=coords[1] if coords else None,
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
                    "geo_precision": precision,
                },
            )
        )
    return out


class PIAProvider:
    name = "pia"

    async def fetch_relays(
        self, cache: JsonCache, refresh: bool = False
    ) -> list[Relay]:
        payload = cache.load(CACHE_KEY) if not refresh and cache.fresh(CACHE_KEY) else None
        if payload is None:
            text = await asyncio.to_thread(_http_get_text, SERVERS_URL)
            payload = parse_payload(text)
            cache.save(CACHE_KEY, payload)
        return normalize(payload)
