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
