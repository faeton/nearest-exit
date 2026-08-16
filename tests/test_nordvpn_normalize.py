import json
import urllib.parse
from pathlib import Path

from nearest_exit.cache import JsonCache
from nearest_exit.providers import nordvpn
from nearest_exit.providers.nordvpn import (
    INVENTORY_FIELDS,
    SOURCE_FIELD,
    SOURCE_INVENTORY,
    SOURCE_RECOMMENDATIONS,
    NordVPNProvider,
    _build_rec_url,
    _build_servers_url,
    country_code_to_id,
    normalize,
    prune_inventory,
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
    """The sparse-fieldset /v1/servers payload still feeds normalize() completely."""
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


def test_normalize_survives_pruning():
    """Trimming for the cache must not lose anything normalize() reads."""
    full = normalize(_servers())
    slim = normalize(prune_inventory(_servers()))
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


def test_sparse_fieldset_response_carries_no_bulk_keys():
    """The fixture is a real /v1/servers?fields[...] capture: no fat sub-objects."""
    for s in _servers():
        assert "services" not in s
        assert "groups" not in s
        assert "specifications" not in s
        assert set(s) == {
            "id", "name", "hostname", "station", "ipv6_station",
            "load", "status", "locations", "technologies",
        }
        loc = s["locations"][0]
        assert set(loc) == {"latitude", "longitude", "country"}
        assert set(loc["country"]) == {"code", "name", "city"}
        assert set(loc["country"]["city"]) == {"name"}
        for tech in s["technologies"]:
            assert set(tech) == {"identifier"}


def test_prune_inventory_keeps_only_mappable_protocols():
    pruned = prune_inventory(_servers())
    assert any(
        t["identifier"] == "proxy_ssl" for s in _servers() for t in s["technologies"]
    ), "fixture must contain a technology worth pruning"
    for s in pruned:
        for tech in s["technologies"]:
            assert tech["identifier"] in (
                "wireguard_udp",
                "openvpn_udp",
                "openvpn_tcp",
                "ikev2",
            )


def test_prune_inventory_drops_servers_with_no_usable_protocol():
    """SOCKS proxies and XOR-obfuscated relays cannot be exits here.

    Ordering buckets by hostname puts `socks-*` ahead of `us1234`, so without
    this filter they would crowd out real relays in the candidate set.
    """
    socks = {
        "hostname": "socks-us71.nordvpn.com",
        "technologies": [{"identifier": "socks"}],
    }
    xor = {
        "hostname": "us6249.nordvpn.com",
        "technologies": [
            {"identifier": "openvpn_xor_udp"},
            {"identifier": "openvpn_xor_tcp"},
        ],
    }
    real = {"hostname": "us2943.nordvpn.com", "technologies": [{"identifier": "wireguard_udp"}]}
    kept = prune_inventory([socks, xor, real])
    assert [s["hostname"] for s in kept] == ["us2943.nordvpn.com"]


def test_prune_inventory_keeps_servers_with_no_technologies_key():
    """Missing key means 'not told', which is not the same as 'cannot'."""
    assert prune_inventory([{"hostname": "x"}]) == [{"hostname": "x"}]


def test_prune_inventory_does_not_mutate_input():
    original = _servers()
    prune_inventory(original)
    assert original == _servers()


def test_build_servers_url_requests_a_sparse_fieldset():
    """The dotted `fields[servers.<path>]` spelling works; `fields[]=x` returns 400."""
    url = _build_servers_url()
    assert "fields%5B%5D" not in url and "fields[]" not in url
    for path in INVENTORY_FIELDS:
        assert f"fields[{path}]" in urllib.parse.unquote(url)
    # Everything normalize() and spread() read must be requested explicitly:
    # the API silently omits unknown paths rather than erroring.
    assert "servers.locations.country.city.name" in INVENTORY_FIELDS
    assert "servers.technologies.identifier" in INVENTORY_FIELDS


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


def _se(hostname: str, load: int) -> dict:
    return {"hostname": hostname, "load": load, "locations": [{"country": {"code": "SE"}}]}


def test_spread_ignores_provider_load_when_choosing_candidates():
    """Which servers get *measured* must not depend on NordVPN's own quality signal.

    Sorting a bucket by `load` would mean a busy relay with better peering could
    never become a candidate — a self-fulfilling filter that re-imports exactly
    the provider ranking this tool exists to avoid.
    """
    busy_first = [_se("a", 90), _se("b", 5)]
    quiet_first = [_se("a", 5), _se("b", 90)]
    # Same hostnames, mirrored loads -> same pick.
    assert [s["hostname"] for s in spread(busy_first, 1)] == ["a"]
    assert [s["hostname"] for s in spread(quiet_first, 1)] == ["a"]


def test_spread_is_deterministic_regardless_of_input_order():
    within = [_se("c", 1), _se("a", 99), _se("b", 50)]
    assert [s["hostname"] for s in spread(within, 2)] == ["a", "b"]
    assert [s["hostname"] for s in spread(list(reversed(within)), 2)] == ["a", "b"]


def test_spread_keeps_load_on_the_selected_servers():
    """load must survive selection: it is still a post-measurement tiebreaker."""
    picked = spread([_se("a", 90), _se("b", 5)], 1)
    assert picked[0]["load"] == 90
    assert normalize(spread(_servers(), 2))[0].load is not None


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


def test_inventory_cache_key_is_versioned():
    """A shape change must not read back caches written in the old shape."""
    assert nordvpn.CACHE_KEY_INVENTORY == "nordvpn-inventory-v3"


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


async def test_fetch_relays_warns_on_stderr_when_falling_back(tmp_path, monkeypatch, capsys):
    """No caller inspects the provider object, so the warning must be unmissable."""
    def fake_get(url, timeout=15.0):
        if "recommendations" in url:
            return _recommendations()
        raise TimeoutError("inventory unavailable")

    monkeypatch.setattr(nordvpn, "_http_get", fake_get)
    await NordVPNProvider(limit=3).fetch_relays(JsonCache(tmp_path))

    err = capsys.readouterr().err
    assert "WARNING" in err
    assert nordvpn.REC_URL in err
    assert "TimeoutError" in err and "inventory unavailable" in err


async def test_fetch_relays_is_quiet_on_the_happy_path(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(nordvpn, "_http_get", lambda url, timeout=15.0: _servers())
    await NordVPNProvider(limit=2).fetch_relays(JsonCache(tmp_path))
    assert capsys.readouterr().err == ""


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
