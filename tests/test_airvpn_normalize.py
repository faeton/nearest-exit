import json
from pathlib import Path

from nearest_exit.cities import city_coords
from nearest_exit.countries import country_centroid
from nearest_exit.providers.airvpn import normalize

FIXTURE = Path(__file__).parent / "fixtures" / "airvpn_status.json"


def test_normalize_basic():
    payload = json.loads(FIXTURE.read_text())
    relays = normalize(payload)
    assert len(relays) >= 1
    r = relays[0]
    assert r.provider == "airvpn"
    assert r.hostname  # public_name
    assert r.ipv4
    assert r.country_code and r.country_code.islower()
    assert "openvpn" in r.protocols and "wireguard" in r.protocols


def test_normalize_preserves_multi_entry_ips():
    payload = json.loads(FIXTURE.read_text())
    relays = normalize(payload)
    r = next((r for r in relays if r.metadata.get("entry_ipv4_all")), None)
    assert r is not None
    assert isinstance(r.metadata["entry_ipv4_all"], list)
    assert len(r.metadata["entry_ipv4_all"]) >= 1


def test_normalize_health_active_flag():
    payload = json.loads(FIXTURE.read_text())
    relays = normalize(payload)
    for r in relays:
        if r.metadata.get("health") == "ok":
            assert r.active is True


def test_every_relay_has_coords():
    payload = json.loads(FIXTURE.read_text())
    relays = normalize(payload)
    assert relays
    for r in relays:
        assert r.latitude is not None and r.longitude is not None, r.hostname


def test_known_cities_get_city_precision():
    payload = json.loads(FIXTURE.read_text())
    relays = normalize(payload)
    zurich = next(r for r in relays if r.country_code == "ch")
    assert (zurich.latitude, zurich.longitude) == city_coords("ch", "Zurich")
    assert zurich.metadata["geo_precision"] == "city"
    # AirVPN qualifies some cities ("Toronto, Ontario"); the head must resolve.
    toronto = next(r for r in relays if r.city == "Toronto, Ontario")
    assert (toronto.latitude, toronto.longitude) == city_coords("ca", "Toronto")
    assert toronto.metadata["geo_precision"] == "city"


def _synthetic(country_code, location):
    return {
        "servers": [
            {
                "public_name": "Testicus",
                "ip_v4_in1": "203.0.113.7",
                "country_code": country_code,
                "location": location,
                "health": "ok",
            }
        ]
    }


def test_unknown_city_falls_back_to_country_centroid():
    (relay,) = normalize(_synthetic("CH", "Some Village"))
    assert (relay.latitude, relay.longitude) == country_centroid("ch")
    assert relay.metadata["geo_precision"] == "country"


def test_unknown_country_has_no_coords():
    (relay,) = normalize(_synthetic("ZZ", "Some Village"))
    assert relay.latitude is None and relay.longitude is None
    assert relay.metadata["geo_precision"] is None
