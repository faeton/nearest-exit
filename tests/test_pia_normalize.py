from pathlib import Path

from nearest_exit.cities import city_coords
from nearest_exit.countries import country_centroid
from nearest_exit.providers.pia import _region_city, normalize, parse_payload
from nearest_exit.subdivisions import subdivision_coords

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


def test_state_region_gets_region_precision():
    (relay,) = normalize(_synthetic("US", "US North Carolina", "us_north_carolina-pf"))
    assert (relay.latitude, relay.longitude) == subdivision_coords("us", "North Carolina")
    assert relay.metadata["geo_precision"] == "region"


def test_subdivision_resolves_from_id_when_label_has_a_suffix():
    # The label reads "CA Ontario Streaming Optimized"; only the id still says Ontario.
    (relay,) = normalize(
        _synthetic("CA", "CA Ontario Streaming Optimized", "ca_ontario-so")
    )
    assert (relay.latitude, relay.longitude) == subdivision_coords("ca", "Ontario")
    assert relay.metadata["geo_precision"] == "region"


def test_city_beats_subdivision():
    # Both tables could answer "CA Toronto"; the city table must win.
    (relay,) = normalize(_synthetic("CA", "CA Toronto", "ca_toronto"))
    assert (relay.latitude, relay.longitude) == city_coords("ca", "Toronto")
    assert relay.metadata["geo_precision"] == "city"


def test_marketing_regions_stay_at_country_precision():
    # Not places: no state point may be invented for them. "US Wilmington" is
    # ambiguous between Delaware and North Carolina and the payload never says.
    for name, region_id in (
        ("US East", "us-newjersey"),
        ("US West", "us3"),
        ("US East Streaming Optimized", "us-streaming"),
        ("US Wilmington", "us-wilmington"),
    ):
        (relay,) = normalize(_synthetic("US", name, region_id))
        assert relay.metadata["geo_precision"] == "country", name
        assert (relay.latitude, relay.longitude) == country_centroid("us")


def test_precision_fallback_chain_is_city_region_country_none():
    cases = [
        (("DE", "DE Berlin", "de_berlin"), "city"),
        (("US", "US Texas", "us_south_west"), "region"),
        (("US", "US East", "us-newjersey"), "country"),
        (("ZZ", "Nowhere", "zz"), None),
    ]
    for args, expected in cases:
        (relay,) = normalize(_synthetic(*args))
        assert relay.metadata["geo_precision"] == expected, args


def test_city_label_strips_pias_country_tag_when_it_names_a_real_city():
    """`--city Berlin` matched `r.city` exactly, and PIA stored "DE Berlin",
    so PIA relays were invisible to a filter that worked everywhere else —
    while the coordinates were already looked up under the stripped name."""
    relays = normalize({
        "regions": [
            {"id": "de-berlin", "name": "DE Berlin", "country": "DE",
             "servers": {"wg": [{"ip": "192.0.2.1", "cn": "berlin"}]}},
        ]
    })

    assert [r.city for r in relays] == ["Berlin"]


def test_city_label_keeps_a_region_name_that_is_not_a_city():
    """"US East" is a region, not a city. Stripping the tag would leave a
    meaningless "East", so the label is only shortened when what remains is
    something the city table recognises."""
    relays = normalize({
        "regions": [
            {"id": "us-east", "name": "US East", "country": "US",
             "servers": {"wg": [{"ip": "192.0.2.2", "cn": "east"}]}},
        ]
    })

    assert [r.city for r in relays] == ["US East"]


def test_city_label_recovers_a_city_the_country_named_label_hides():
    """PIA names some regions after the country while the id names the city:
    "Netherlands" is nl_amsterdam. Coordinates already came from that id, so
    the stored label disagreed with the relay's own position and
    `--city Amsterdam` could not find it."""
    relays = normalize({
        "regions": [
            {"id": "nl_amsterdam", "name": "Netherlands", "country": "NL",
             "servers": {"wg": [{"ip": "192.0.2.3", "cn": "nl"}]}},
        ]
    })

    assert [r.city for r in relays] == ["Amsterdam"]


def test_city_label_uses_the_tables_spelling_not_the_slugs():
    """The slug is lower-case with underscores. Title-casing it would render
    some names correctly and mangle any the table spells deliberately."""
    relays = normalize({
        "regions": [
            {"id": "us_new_york_city", "name": "US New York", "country": "US",
             "servers": {"wg": [{"ip": "192.0.2.4", "cn": "us"}]}},
        ]
    })

    assert [r.city for r in relays] == ["New York"]


def test_city_label_leaves_a_region_with_no_city_anywhere_alone():
    relays = normalize({
        "regions": [
            {"id": "us_west", "name": "US West", "country": "US",
             "servers": {"wg": [{"ip": "192.0.2.5", "cn": "us"}]}},
        ]
    })

    assert [r.city for r in relays] == ["US West"]
