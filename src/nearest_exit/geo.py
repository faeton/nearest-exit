from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from . import stun
from .countries import country_centroid

USER_AGENT = "nearest-exit/0.0.1"


@dataclass
class GeoContext:
    ip: str | None = None
    asn: str | None = None
    org: str | None = None
    city: str | None = None
    country_code: str | None = None
    country_name: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    source: str = "none"


def lookup_ipinfo(timeout: float = 4.0) -> GeoContext:
    """Geolocation via ipinfo.io (anonymous tier).

    HTTPS dependency. Returns approximate city/country/coords from the
    requester's public IP."""
    url = "https://ipinfo.io/json"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
            data = json.load(r)
    except Exception:
        return GeoContext(source="ipinfo-failed")

    lat = lon = None
    loc = data.get("loc")
    if loc and "," in loc:
        try:
            a, b = loc.split(",", 1)
            lat, lon = float(a), float(b)
        except ValueError:
            pass

    org = data.get("org") or ""
    asn = None
    if org.startswith("AS"):
        parts = org.split(" ", 1)
        asn = parts[0]

    return GeoContext(
        ip=data.get("ip"),
        asn=asn,
        org=org or None,
        city=data.get("city"),
        country_code=(data.get("country") or "").lower() or None,
        latitude=lat,
        longitude=lon,
        source="ipinfo",
    )


def lookup_stun(timeout: float = 2.0) -> GeoContext:
    """Public IP via STUN. UDP only — no HTTP, no JSON. Does not resolve
    country/coords on its own; combine with `apply_mmdb()` or with manual
    override for full context."""
    ip = stun.public_ip(timeout=timeout)
    if not ip:
        return GeoContext(source="stun-failed")
    return GeoContext(ip=ip, source="stun")


def apply_mmdb(geo: GeoContext, mmdb_path: str | Path) -> GeoContext:
    """If MaxMind GeoLite2-City (or compatible) MMDB is present, resolve
    the IP locally without any network call. Optional dependency."""
    if not geo.ip:
        return geo
    try:
        import maxminddb  # type: ignore
    except ImportError:
        return geo
    p = Path(mmdb_path).expanduser()
    if not p.exists():
        return geo
    try:
        with maxminddb.open_database(str(p)) as r:
            d = r.get(geo.ip) or {}
    except Exception:
        return geo
    country = (d.get("country") or {})
    city = (d.get("city") or {})
    location = (d.get("location") or {})
    cc = (country.get("iso_code") or "").lower() or None
    return GeoContext(
        ip=geo.ip,
        asn=geo.asn,
        org=geo.org,
        city=(city.get("names") or {}).get("en") or geo.city,
        country_code=cc or geo.country_code,
        country_name=(country.get("names") or {}).get("en") or geo.country_name,
        latitude=location.get("latitude") or geo.latitude,
        longitude=location.get("longitude") or geo.longitude,
        source=f"{geo.source}+mmdb",
    )


def from_override(
    country: str | None = None,
    coords: tuple[float, float] | None = None,
) -> GeoContext:
    """Build a GeoContext from explicit user-supplied values. No network."""
    cc = country.lower() if country else None
    lat = lon = None
    if coords:
        lat, lon = coords
    elif cc:
        c = country_centroid(cc)
        if c:
            lat, lon = c
    return GeoContext(
        country_code=cc,
        latitude=lat,
        longitude=lon,
        source="override",
    )


def resolve_geo(
    lookup: str,
    override_country: str | None = None,
    override_coords: tuple[float, float] | None = None,
    mmdb_path: str | None = None,
) -> GeoContext:
    """Single entry point honoring config / CLI override / pluggable lookup."""
    if override_country or override_coords:
        return from_override(override_country, override_coords)
    if lookup == "none":
        return GeoContext(source="none")
    if lookup == "stun":
        geo = lookup_stun()
        if mmdb_path:
            geo = apply_mmdb(geo, mmdb_path)
        return geo
    geo = lookup_ipinfo()
    if mmdb_path and geo.ip:
        geo = apply_mmdb(geo, mmdb_path)
    return geo
