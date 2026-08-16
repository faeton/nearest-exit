from __future__ import annotations

from collections import defaultdict

from .geofilter import haversine_km
from .models import Relay

# metadata['geo_precision'] values. Providers that publish real per-relay
# coordinates report EXACT; providers that only publish a country code get
# coordinates back-filled from EMBEDDED_CENTROIDS and report COUNTRY.
GEO_PRECISION_EXACT = "exact"
GEO_PRECISION_COUNTRY = "country"


def centroids_from_relays(
    relays: list[Relay],
) -> dict[str, tuple[float, float]]:
    """Build country-centroid table (cc → mean lat/lon) from relays that
    expose coordinates. Used to choose geographically-nearest neighbor
    countries without depending on an external geo database."""
    by_cc: dict[str, list[tuple[float, float]]] = defaultdict(list)
    for r in relays:
        if not r.country_code or r.latitude is None or r.longitude is None:
            continue
        # Country-derived coords are copies of the embedded centroid; feeding
        # them back in would make this table self-referential rather than a
        # measurement of where relays actually are.
        if r.metadata.get("geo_precision") == GEO_PRECISION_COUNTRY:
            continue
        by_cc[r.country_code.lower()].append((r.latitude, r.longitude))
    out: dict[str, tuple[float, float]] = {}
    for cc, pts in by_cc.items():
        out[cc] = (
            sum(p[0] for p in pts) / len(pts),
            sum(p[1] for p in pts) / len(pts),
        )
    return out


def nearest_countries(
    centroids: dict[str, tuple[float, float]],
    lat: float,
    lon: float,
    k: int,
    exclude: set[str] | None = None,
) -> list[tuple[str, float]]:
    """Return up to k (country_code, distance_km) tuples, nearest first."""
    excl = {c.lower() for c in (exclude or set())}
    items = [
        (cc, haversine_km(lat, lon, c[0], c[1]))
        for cc, c in centroids.items()
        if cc.lower() not in excl
    ]
    items.sort(key=lambda x: x[1])
    return items[:k]


# Embedded centroids — fallback when the relay-derived map does not contain
# the user's detected country (e.g. user is in a country no provider covers),
# and the source of country-derived relay coordinates for providers that ship
# no per-server geo (AirVPN, PIA), so every country those two serve must have
# an entry here. Accurate to roughly the country's geographic center;
# relay-derived centroids take precedence when available.
EMBEDDED_CENTROIDS: dict[str, tuple[float, float]] = {
    # Middle East
    "ye": (15.5, 48.5), "sa": (24.0, 45.0), "ae": (24.0, 54.0),
    "om": (21.0, 57.0), "qa": (25.3, 51.2), "kw": (29.5, 47.8),
    "bh": (26.0, 50.5), "iq": (33.0, 44.0), "ir": (32.0, 53.0),
    "jo": (31.0, 36.0), "il": (31.5, 35.0), "lb": (33.9, 35.5),
    "sy": (35.0, 38.0), "tr": (39.0, 35.0),
    # Africa
    "eg": (27.0, 30.0), "ly": (27.0, 17.0), "tn": (34.0, 9.0),
    "dz": (28.0, 3.0), "ma": (32.0, -6.0), "et": (8.0, 38.0),
    "dj": (11.5, 43.0), "so": (5.0, 46.0), "er": (15.0, 39.0),
    "sd": (15.0, 30.0), "ng": (10.0, 8.0), "ke": (-1.0, 38.0),
    "za": (-29.0, 24.0), "tz": (-6.0, 35.0), "ug": (1.0, 32.0),
    # Europe
    "de": (51.0, 10.0), "fr": (46.0, 2.0), "gb": (54.0, -2.0),
    "nl": (52.0, 5.5), "be": (50.5, 4.5), "se": (60.0, 18.0),
    "no": (62.0, 10.0), "fi": (64.0, 26.0), "dk": (56.0, 10.0),
    "es": (40.0, -4.0), "pt": (39.5, -8.0), "it": (42.5, 12.5),
    "ch": (47.0, 8.0), "at": (47.5, 14.0), "pl": (52.0, 19.0),
    "cz": (49.8, 15.5), "ro": (46.0, 25.0), "bg": (43.0, 25.0),
    "gr": (39.0, 22.0), "rs": (44.0, 21.0), "hr": (45.0, 16.0),
    "ua": (49.0, 32.0), "ru": (60.0, 100.0), "ie": (53.0, -8.0),
    "hu": (47.0, 20.0), "sk": (48.7, 19.5), "si": (46.1, 14.8),
    "ba": (44.0, 18.0), "me": (42.5, 19.3), "mk": (41.6, 21.7),
    "al": (41.0, 20.0), "md": (47.0, 28.5), "ee": (59.0, 26.0),
    "lv": (57.0, 25.0), "lt": (55.2, 24.0), "is": (65.0, -18.0),
    "lu": (49.8, 6.1), "li": (47.2, 9.5), "mc": (43.7, 7.4),
    "ad": (42.5, 1.5), "mt": (35.9, 14.4), "cy": (35.0, 33.0),
    "im": (54.2, -4.5),
    # Americas
    "us": (38.0, -97.0), "ca": (60.0, -96.0), "mx": (23.0, -102.0),
    "br": (-10.0, -55.0), "ar": (-34.0, -64.0), "cl": (-30.0, -71.0),
    "co": (4.0, -72.0), "pe": (-10.0, -76.0), "ve": (8.0, -66.0),
    "uy": (-33.0, -56.0), "bo": (-17.0, -65.0), "ec": (-1.5, -78.5),
    "pa": (8.5, -80.0), "cr": (10.0, -84.0), "gt": (15.5, -90.3),
    "bs": (24.5, -77.5), "gl": (72.0, -40.0),
    # Asia / Oceania
    "in": (22.0, 79.0), "pk": (30.0, 70.0), "cn": (35.0, 105.0),
    "jp": (36.0, 138.0), "kr": (37.0, 127.5), "tw": (24.0, 121.0),
    "hk": (22.3, 114.2), "sg": (1.4, 103.8), "my": (4.0, 108.0),
    "th": (15.0, 100.0), "vn": (16.0, 108.0), "id": (-2.0, 118.0),
    "ph": (13.0, 122.0), "au": (-25.0, 133.0), "nz": (-41.0, 174.0),
    "mo": (22.2, 113.5), "kh": (12.5, 105.0), "np": (28.3, 84.0),
    "bd": (24.0, 90.0), "lk": (7.5, 80.7), "mn": (46.5, 103.0),
    "kz": (48.0, 68.0), "ge": (42.0, 43.5), "am": (40.3, 45.0),
}


def merged_centroids(
    relays: list[Relay],
) -> dict[str, tuple[float, float]]:
    """Relay-derived centroids overlay the embedded fallback table."""
    out = dict(EMBEDDED_CENTROIDS)
    out.update(centroids_from_relays(relays))
    return out


def country_centroid(
    cc: str, centroids: dict[str, tuple[float, float]] | None = None
) -> tuple[float, float] | None:
    table = centroids if centroids is not None else EMBEDDED_CENTROIDS
    return table.get(cc.lower())
