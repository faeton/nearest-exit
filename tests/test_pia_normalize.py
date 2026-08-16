from pathlib import Path

from nearest_exit.cities import city_coords
from nearest_exit.countries import country_centroid
from nearest_exit.providers.pia import _region_city, normalize, parse_payload

FIXTURE = Path(__file__).parent / "fixtures" / "pia_servers_v6.txt"


def test_parse_strips_signature_tail():
    text = FIXTURE.read_text()
    payload = parse_payload(text)
    assert "regions" in payload and "groups" in payload
    assert isinstance(payload["regions"], list)


def test_normalize_basic():
    payload = parse_payload(FIXTURE.read_text())
    relays = normalize(payload)
    ids = {r.id for r in relays}
    assert "us_atlanta" in ids and "de_berlin" in ids
    atl = next(r for r in relays if r.id == "us_atlanta")
    assert atl.provider == "pia"
    assert atl.country_code == "us"
    # WireGuard IP is the canonical probe target.
    assert atl.ipv4 == "154.21.0.3"
    assert "wireguard" in atl.protocols
    assert "openvpn" in atl.protocols
    assert "socks5" in atl.protocols
    assert atl.metadata["dns"] == "atlanta.privacy.network"


def test_offline_region_inactive():
    payload = parse_payload(FIXTURE.read_text())
    relays = normalize(payload)
    hk = next(r for r in relays if r.id == "hk")
    assert hk.active is False
    assert hk.metadata["geo"] is True


def test_port_forward_preserved():
    payload = parse_payload(FIXTURE.read_text())
    relays = normalize(payload)
    berlin = next(r for r in relays if r.id == "de_berlin")
    assert berlin.metadata["port_forward"] is True


def test_every_relay_has_coords():
    payload = parse_payload(FIXTURE.read_text())
    relays = normalize(payload)
    assert relays
    for r in relays:
        assert r.latitude is not None and r.longitude is not None, r.id


def test_country_tagged_names_get_city_precision():
    payload = parse_payload(FIXTURE.read_text())
    relays = normalize(payload)
    atl = next(r for r in relays if r.id == "us_atlanta")
    assert (atl.latitude, atl.longitude) == city_coords("us", "Atlanta")
    assert atl.metadata["geo_precision"] == "city"
    berlin = next(r for r in relays if r.id == "de_berlin")
    assert (berlin.latitude, berlin.longitude) == city_coords("de", "Berlin")
    assert berlin.metadata["geo_precision"] == "city"
    # Untagged single-city region names resolve as-is.
    hk = next(r for r in relays if r.id == "hk")
    assert (hk.latitude, hk.longitude) == city_coords("hk", "Hong Kong")
    assert hk.metadata["geo_precision"] == "city"


def test_region_city_strips_only_country_tags():
    assert _region_city("DE Berlin", "de") == "Berlin"
    assert _region_city("UK London", "gb") == "London"  # PIA says UK, not GB.
    assert _region_city("Hong Kong", "hk") == "Hong Kong"
    assert _region_city("US East", "us") == "East"  # Not a city; misses the table.
    assert _region_city("Costa Rica", "cr") == "Costa Rica"
    assert _region_city(None, "us") is None


def _synthetic(country, name, region_id):
    return {
        "groups": {},
        "regions": [
            {
                "id": region_id,
                "name": name,
                "country": country,
                "dns": f"{region_id}.example",
                "servers": {"wg": [{"ip": "203.0.113.7", "cn": "test"}]},
            }
        ],
    }


def test_non_city_region_falls_back_to_country_centroid():
    (relay,) = normalize(_synthetic("US", "US East", "us-newjersey"))
    assert (relay.latitude, relay.longitude) == country_centroid("us")
    assert relay.metadata["geo_precision"] == "country"


def test_country_named_region_resolves_city_from_id():
    (relay,) = normalize(_synthetic("NL", "Netherlands", "nl_amsterdam"))
    assert (relay.latitude, relay.longitude) == city_coords("nl", "Amsterdam")
    assert relay.metadata["geo_precision"] == "city"


def test_unknown_country_has_no_coords():
    (relay,) = normalize(_synthetic("ZZ", "Nowhere", "zz"))
    assert relay.latitude is None and relay.longitude is None
    assert relay.metadata["geo_precision"] is None
