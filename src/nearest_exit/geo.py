from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass

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


def lookup_ipinfo(timeout: float = 4.0) -> GeoContext:
    """Cheap geolocation via ipinfo.io. Anonymous tier returns approximate
    city/country/loc. No API key needed for low-volume use."""
    url = "https://ipinfo.io/json"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
            data = json.load(r)
    except Exception:
        return GeoContext()

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
        country_name=None,
        latitude=lat,
        longitude=lon,
    )
