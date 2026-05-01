from nearest_exit.countries import (
    EMBEDDED_CENTROIDS,
    centroids_from_relays,
    country_centroid,
    merged_centroids,
    nearest_countries,
)
from nearest_exit.models import Relay


def relay(cc: str, lat: float, lon: float, host: str = "h") -> Relay:
    return Relay(
        provider="t", id=f"{cc}-{host}", hostname=f"{cc}-{host}",
        country_code=cc, ipv4="1.2.3.4", latitude=lat, longitude=lon,
    )


def test_centroids_average_per_country():
    relays = [
        relay("us", 40.0, -74.0, "nyc"),
        relay("us", 34.0, -118.0, "lax"),
        relay("de", 50.0, 8.0, "fra"),
    ]
    c = centroids_from_relays(relays)
    assert "us" in c and "de" in c
    assert abs(c["us"][0] - 37.0) < 0.01
    assert abs(c["us"][1] - (-96.0)) < 0.01


def test_nearest_countries_from_yemen_picks_neighbors():
    # Yemen ~ (15.5, 48.5). Embedded table has SA, OM, AE, DJ, ER, ET, SO etc.
    nearest = nearest_countries(EMBEDDED_CENTROIDS, 15.5, 48.5, k=5)
    cc_set = {cc for cc, _ in nearest}
    # Should include at least 3 of these geographic neighbors:
    expected_neighbors = {"sa", "om", "dj", "er", "so", "et", "ae"}
    assert len(cc_set & expected_neighbors) >= 3, cc_set


def test_nearest_excludes_self():
    nearest = nearest_countries(
        EMBEDDED_CENTROIDS, 15.5, 48.5, k=5, exclude={"ye"},
    )
    assert "ye" not in {cc for cc, _ in nearest}


def test_country_centroid_lookup():
    assert country_centroid("YE") is not None
    assert country_centroid("ye") is not None
    assert country_centroid("zz") is None


def test_merged_overrides_with_relays():
    relays = [relay("us", 99.0, 99.0)]   # absurd to make sure it overrides
    m = merged_centroids(relays)
    assert m["us"] == (99.0, 99.0)
    # Embedded values still present for countries we didn't override:
    assert m["de"] == EMBEDDED_CENTROIDS["de"]
