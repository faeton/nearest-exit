from __future__ import annotations

import math

from .models import Relay


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
    Relays missing coords are kept but ranked after those with coords.
    """
    if k <= 0:
        return relays
    if lat is None or lon is None:
        return relays[:k]

    def key(r: Relay) -> tuple[int, float, str]:
        if r.latitude is None or r.longitude is None:
            return (1, math.inf, r.hostname)
        return (0, haversine_km(lat, lon, r.latitude, r.longitude), r.hostname)

    return sorted(relays, key=key)[:k]
