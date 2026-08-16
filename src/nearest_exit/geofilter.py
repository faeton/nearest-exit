from __future__ import annotations

import heapq
import math

from .models import GEO_PRECISION_COUNTRY, GEO_PRECISION_REGION, Relay

# A country-derived coordinate is the country's centre, so the relay could be
# anywhere within roughly this much of it. Charging that uncertainty as extra
# distance stops a coarse guess from outranking a relay whose position we
# actually know — the true error averages ~650km for AirVPN and ~1100km for
# PIA against their real city coordinates.
COUNTRY_PRECISION_UNCERTAINTY_KM = 750.0

# A subdivision-derived coordinate is a state's or province's population-weighted
# centre, and capacity is sited roughly in proportion to population, so the
# expected miss is the mean distance from that centre to a resident. Over the 38
# states PIA labels, computed from the Census Bureau's 2020 county centers of
# population, that is 142km unweighted and 155km once states are weighted by
# their own population; 150km sits between the two. Charging a country's 750km
# here would throw away most of what the finer position buys.
REGION_PRECISION_UNCERTAINTY_KM = 150.0

_PRECISION_UNCERTAINTY_KM = {
    GEO_PRECISION_COUNTRY: COUNTRY_PRECISION_UNCERTAINTY_KM,
    GEO_PRECISION_REGION: REGION_PRECISION_UNCERTAINTY_KM,
}


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance between two (lat, lon) points in kilometers."""
    R = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlam = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlam / 2) ** 2
    return 2 * R * math.asin(math.sqrt(a))


def top_k_by_distance(
    relays: list[Relay],
    lat: float | None,
    lon: float | None,
    k: int,
) -> list[Relay]:
    """Return the K relays nearest to (lat, lon).

    If user coords are unknown, the original order is preserved (truncated to k).
    Relays missing coords are kept but ranked after those with coords, and
    relays positioned only to their subdivision or country carry a distance
    penalty for how little that position says.
    """
    if k <= 0:
        return relays
    if lat is None or lon is None:
        return relays[:k]

    def key(r: Relay) -> tuple[int, float, str]:
        if r.latitude is None or r.longitude is None:
            return (1, math.inf, r.hostname)
        distance = haversine_km(lat, lon, r.latitude, r.longitude)
        distance += _PRECISION_UNCERTAINTY_KM.get(r.metadata.get("geo_precision"), 0.0)
        return (0, distance, r.hostname)

    # nsmallest avoids a full O(n log n) sort of the ~6k-relay pool for a
    # handful of picks; it is defined to match sorted(...)[:k] on ties.
    return heapq.nsmallest(k, relays, key=key)
