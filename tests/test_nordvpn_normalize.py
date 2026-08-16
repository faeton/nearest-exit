import json
from pathlib import Path

from nearest_exit.cache import JsonCache
from nearest_exit.providers import nordvpn
from nearest_exit.providers.nordvpn import (
    SOURCE_FIELD,
    SOURCE_INVENTORY,
    SOURCE_RECOMMENDATIONS,
    NordVPNProvider,
    _build_rec_url,
    _build_servers_url,
    country_code_to_id,
    normalize,
    slim_inventory,
    spread,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _servers():
    return json.loads((FIXTURES / "nordvpn_servers.json").read_text())


def _recommendations():
    return json.loads((FIXTURES / "nordvpn_recommendations.json").read_text())


def test_normalize_basic_fields():
    relays = normalize(_recommendations())
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
    relays = normalize(_recommendations())
    for r in relays:
        # openvpn_udp and openvpn_tcp should both collapse to a single "openvpn"
        assert r.protocols.count("openvpn") <= 1


def test_normalize_handles_inventory_response():
    """/v1/servers returns the same object shape as /recommendations."""
    relays = normalize(_servers())
    assert len(relays) == 4
    for r in relays:
        assert r.hostname.endswith(".nordvpn.com")
        assert r.ipv4
        assert r.country_code and r.country_code.islower()
        assert r.city
        assert r.latitude is not None and r.longitude is not None
        assert r.active is True
        assert "wireguard" in r.protocols


def test_normalize_survives_slimming():
    """Trimming for the cache must not lose anything normalize() reads."""
    full = normalize(_servers())
    slim = normalize(slim_inventory(_servers()))
    for a, b in zip(full, slim, strict=True):
        assert (a.id, a.hostname, a.ipv4, a.country_code, a.city) == (
            b.id,
            b.hostname,
            b.ipv4,
            b.country_code,
            b.city,
        )
        assert (a.latitude, a.longitude, a.load, a.active) == (
            b.latitude,
            b.longitude,
            b.load,
            b.active,
        )
        assert a.protocols == b.protocols


def test_slim_inventory_drops_bulk_fields():
    slim = slim_inventory(_servers())
    for s in slim:
        assert "services" not in s
        assert "groups" not in s
        assert "specifications" not in s
        for tech in s["technologies"]:
            assert tech["identifier"] in (
                "wireguard_udp",
                "openvpn_udp",
                "openvpn_tcp",
                "ikev2",
            )


def test_normalize_stamps_source():
    relays = normalize(_servers(), source=SOURCE_RECOMMENDATIONS)
    assert all(r.metadata[SOURCE_FIELD] == SOURCE_RECOMMENDATIONS for r in relays)
    assert all(SOURCE_FIELD not in r.metadata for r in normalize(_servers()))


def test_country_code_to_id():
    countries = json.loads((FIXTURES / "nordvpn_countries.json").read_text())
    al = country_code_to_id(countries, "AL")
    assert al == 2
    af_lower = country_code_to_id(countries, "af")
    assert af_lower == 1
    by_name = country_code_to_id(countries, "Algeria")
    assert by_name == 3
    assert country_code_to_id(countries, "ZZ") is None


def test_build_servers_url_targets_inventory_not_recommendations():
    url = _build_servers_url()
    assert url.startswith("https://api.nordvpn.com/v1/servers?")
    assert "recommendations" not in url
    # limit=0 is NordVPN's "everything" sentinel.
    assert "limit=0" in url


def test_build_servers_url_includes_filters():
    url = _build_servers_url(0, country_id=227, technology="wireguard_udp")
    assert "recommendations" not in url
    assert "country_id" in url and "227" in url
    assert "wireguard_udp" in url


def test_build_rec_url_includes_filters():
    url = _build_rec_url(10, country_id=42, technology="wireguard_udp")
    assert "limit=10" in url
    assert "country_id" in url and "42" in url
    assert "wireguard_udp" in url


def test_build_rec_url_minimal():
    url = _build_rec_url(5)
    assert url.endswith("?limit=5")


def test_spread_covers_cities_instead_of_taking_a_prefix():
    servers = _servers()
    # The fixture is id-ordered: GB, FR, US/Dallas, US/Los Angeles.
    assert [s["locations"][0]["country"]["code"] for s in servers[:2]] == ["GB", "FR"]

    picked = spread(servers, 3)
    assert len(picked) == 3
    cities = {
        (
            s["locations"][0]["country"]["code"],
            s["locations"][0]["country"]["city"]["name"],
        )
        for s in picked
    }
    assert len(cities) == 3


def test_spread_is_a_noop_when_limit_covers_everything():
    servers = _servers()
    assert spread(servers, 0) == servers
    assert spread(servers, 99) == servers


def test_spread_prefers_low_load_within_a_city():
    a = {"hostname": "a", "load": 90, "locations": [{"country": {"code": "SE"}}]}
    b = {"hostname": "b", "load": 5, "locations": [{"country": {"code": "SE"}}]}
    assert [s["hostname"] for s in spread([a, b], 1)] == ["b"]


async def test_fetch_relays_uses_inventory(tmp_path, monkeypatch):
    seen: list[str] = []

    def fake_get(url, timeout=15.0):
        seen.append(url)
        return _servers()

    monkeypatch.setattr(nordvpn, "_http_get", fake_get)
    provider = NordVPNProvider(country_id=227, technology="wireguard_udp", limit=2)
    relays = await provider.fetch_relays(JsonCache(tmp_path))

    assert len(seen) == 1
    assert "/v1/servers?" in seen[0] and "recommendations" not in seen[0]
    assert provider.source == SOURCE_INVENTORY
    assert len(relays) == 2
    assert all(r.metadata[SOURCE_FIELD] == SOURCE_INVENTORY for r in relays)


async def test_fetch_relays_caches_the_trimmed_shape(tmp_path, monkeypatch):
    calls: list[str] = []

    def fake_get(url, timeout=15.0):
        calls.append(url)
        return _servers()

    monkeypatch.setattr(nordvpn, "_http_get", fake_get)
    cache = JsonCache(tmp_path)
    await NordVPNProvider(limit=2).fetch_relays(cache)
    # A different --limit must reuse the cached inventory rather than refetch.
    await NordVPNProvider(limit=4).fetch_relays(cache)
    assert len(calls) == 1

    cached = cache.load(f"{nordvpn.CACHE_KEY_INVENTORY}-cany-tany")
    assert "services" not in cached[0]
    assert len(json.dumps(cached)) < len(json.dumps(_servers()))


async def test_fetch_relays_falls_back_visibly(tmp_path, monkeypatch):
    def fake_get(url, timeout=15.0):
        if "recommendations" in url:
            return _recommendations()
        raise TimeoutError("inventory unavailable")

    monkeypatch.setattr(nordvpn, "_http_get", fake_get)
    provider = NordVPNProvider(limit=3)
    relays = await provider.fetch_relays(JsonCache(tmp_path))

    assert provider.source == SOURCE_RECOMMENDATIONS
    assert provider.fallback_reason and "TimeoutError" in provider.fallback_reason
    assert relays
    assert all(r.metadata[SOURCE_FIELD] == SOURCE_RECOMMENDATIONS for r in relays)


async def test_fetch_relays_can_refuse_the_fallback(tmp_path, monkeypatch):
    def fake_get(url, timeout=15.0):
        raise TimeoutError("inventory unavailable")

    monkeypatch.setattr(nordvpn, "_http_get", fake_get)
    provider = NordVPNProvider(allow_recommendation_fallback=False)
    try:
        await provider.fetch_relays(JsonCache(tmp_path))
    except TimeoutError:
        pass
    else:
        raise AssertionError("expected the inventory failure to propagate")
