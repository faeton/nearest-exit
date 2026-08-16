from nearest_exit.geofilter import haversine_km, top_k_by_distance
from nearest_exit.models import Relay


def relay(hostname: str, lat: float | None = None, lon: float | None = None) -> Relay:
    return Relay(
        provider="t", id=hostname, hostname=hostname, ipv4="1.2.3.4",
        latitude=lat, longitude=lon,
    )


def test_haversine_known_distance():
    # Berlin → Frankfurt is ~423 km
    d = haversine_km(52.52, 13.405, 50.111, 8.682)
    assert 410 < d < 440


def test_top_k_picks_nearest():
    user = (52.52, 13.405)  # Berlin
    relays = [
        relay("nyc", 40.71, -74.00),
        relay("fra", 50.11, 8.68),
        relay("ams", 52.37, 4.89),
        relay("syd", -33.87, 151.21),
    ]
    # Berlin → Frankfurt ≈ 423 km, Berlin → Amsterdam ≈ 575 km
    picked = top_k_by_distance(relays, *user, k=2)
    assert [r.hostname for r in picked] == ["fra", "ams"]


def test_top_k_passthrough_when_no_user_coords():
    relays = [relay("a"), relay("b"), relay("c")]
    picked = top_k_by_distance(relays, None, None, k=2)
    assert picked == relays[:2]


def test_top_k_keeps_missing_coords_at_end():
    user = (52.52, 13.405)
    relays = [
        relay("nocoords1"),
        relay("fra", 50.11, 8.68),
        relay("nocoords2"),
    ]
    picked = top_k_by_distance(relays, *user, k=3)
    assert picked[0].hostname == "fra"
    assert {r.hostname for r in picked[1:]} == {"nocoords1", "nocoords2"}


def test_top_k_returns_all_when_k_exceeds_len():
    relays = [relay("a", 0, 0), relay("b", 0, 1)]
    picked = top_k_by_distance(relays, 0, 0, k=10)
    assert len(picked) == 2


def test_top_k_zero_or_negative_returns_input_unchanged():
    relays = [relay("a", 0, 0), relay("b", 0, 1)]
    assert top_k_by_distance(relays, 0, 0, k=0) == relays
    assert top_k_by_distance(relays, 0, 0, k=-1) == relays


def test_top_k_breaks_ties_by_hostname():
    relays = [relay("c", 0, 0), relay("a", 0, 0), relay("b", 0, 0)]
    picked = top_k_by_distance(relays, 0, 0, k=3)
    assert [r.hostname for r in picked] == ["a", "b", "c"]


def test_top_k_returns_a_list():
    picked = top_k_by_distance([relay("a", 0, 0)], 0, 0, k=1)
    assert isinstance(picked, list)


def test_top_k_matches_full_sort():
    # heapq.nsmallest must stay equivalent to the sorted(...)[:k] it replaced.
    relays = [
        relay(f"h{i:02d}", (i * 7) % 90 - 45, (i * 13) % 180 - 90)
        for i in range(40)
    ] + [relay("nocoords")]
    for k in (1, 5, 40, 41, 99):
        picked = top_k_by_distance(relays, 10.0, 20.0, k=k)
        assert [r.hostname for r in picked] == [
            r.hostname for r in sorted(relays, key=_reference_key)[:k]
        ]


def _reference_key(r):
    if r.latitude is None or r.longitude is None:
        return (1, float("inf"), r.hostname)
    return (0, haversine_km(10.0, 20.0, r.latitude, r.longitude), r.hostname)
