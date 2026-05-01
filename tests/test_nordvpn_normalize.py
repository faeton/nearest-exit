import json
from pathlib import Path

from nearest_exit.providers.nordvpn import (
    _build_rec_url,
    country_code_to_id,
    normalize,
)

FIXTURES = Path(__file__).parent / "fixtures"


def test_normalize_basic_fields():
    raw = json.loads((FIXTURES / "nordvpn_recommendations.json").read_text())
    relays = normalize(raw)
    assert len(relays) >= 1

    r = relays[0]
    assert r.provider == "nordvpn"
    assert r.hostname.endswith(".nordvpn.com")
    assert r.ipv4
    assert r.country_code and r.country_code.islower()
    assert r.country_name
    assert r.active is True
    assert r.load is not None and 0 <= r.load <= 100
    assert "wireguard" in r.protocols or "openvpn" in r.protocols


def test_normalize_dedupes_openvpn_variants():
    raw = json.loads((FIXTURES / "nordvpn_recommendations.json").read_text())
    relays = normalize(raw)
    for r in relays:
        # openvpn_udp and openvpn_tcp should both collapse to a single "openvpn"
        assert r.protocols.count("openvpn") <= 1


def test_country_code_to_id():
    countries = json.loads((FIXTURES / "nordvpn_countries.json").read_text())
    al = country_code_to_id(countries, "AL")
    assert al == 2
    af_lower = country_code_to_id(countries, "af")
    assert af_lower == 1
    by_name = country_code_to_id(countries, "Algeria")
    assert by_name == 3
    assert country_code_to_id(countries, "ZZ") is None


def test_build_rec_url_includes_filters():
    url = _build_rec_url(10, country_id=42, technology="wireguard_udp")
    assert "limit=10" in url
    assert "country_id" in url and "42" in url
    assert "wireguard_udp" in url


def test_build_rec_url_minimal():
    url = _build_rec_url(5)
    assert url.endswith("?limit=5")
