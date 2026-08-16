import json
from pathlib import Path

import pytest

from nearest_exit.cache import JsonCache
from nearest_exit.models import GEO_PRECISION_CITY
from nearest_exit.providers import mullvad
from nearest_exit.providers.mullvad import CACHE_KEY, MullvadProvider, normalize
from nearest_exit.targets import socks5_target

# Captured verbatim from https://api.mullvad.net/www/relays/all/ — the previous
# fixture carried latitude/longitude fields the API does not actually return,
# which hid the fact that Mullvad relays had no coordinates.
FIXTURE = Path(__file__).parent / "fixtures" / "mullvad_sample.json"


def _relays():
    return normalize(json.loads(FIXTURE.read_text()))


def test_normalize_basic_fields():
    de = next(r for r in _relays() if r.hostname == "de-ber-wg-001")
    assert de.provider == "mullvad"
    assert de.country_code == "de"
    assert de.country_name == "Germany"
    assert de.city == "Berlin"
    assert de.ipv4
    assert de.ipv6
    assert de.active is True
    assert "wireguard" in de.protocols


def test_normalize_preserves_raw_metadata():
    de = next(r for r in _relays() if r.hostname == "de-ber-wg-001")
    assert de.metadata["network_port_speed"] > 0
    assert de.metadata["provider"]
    assert de.metadata["pubkey"]


def test_normalize_handles_inactive():
    inactive = [r for r in _relays() if r.active is False]
    assert inactive, "fixture should include an inactive relay"


def test_socks5_is_not_advertised_because_the_proxies_are_tunnel_internal():
    """Mullvad publishes socks_name/socks_port on 574 of 587 relays, but every
    one resolves into 10.124.0.0/16 — reachable only from inside a Mullvad
    tunnel, which is the state this tool runs before. Advertising them made
    `--protocol socks5` select relays it could never measure and report the
    timeout as though the relay were slow."""
    de = next(r for r in _relays() if r.hostname == "de-ber-wg-001")

    # The fields are still in the payload; we simply do not act on them.
    assert de.metadata["socks_name"].endswith(".relays.mullvad.net")
    assert de.metadata["socks_port"] == 1080

    assert "socks5" not in de.protocols
    assert "socks5_target" not in de.metadata
    assert socks5_target(de) is None


def test_no_mullvad_relay_advertises_socks5():
    assert not any("socks5" in r.protocols for r in _relays())


async def test_fetch_uses_cache_when_fresh(tmp_path, monkeypatch):
    raw = json.loads(FIXTURE.read_text())
    cache = JsonCache(cache_dir=tmp_path)
    cache.save(CACHE_KEY, raw)
    monkeypatch.setattr(
        mullvad, "_fetch_sync",
        lambda *a, **kw: pytest.fail("network hit despite fresh cache"),
    )
    assert len(await MullvadProvider().fetch_relays(cache)) == len(raw)


async def test_fetch_refetches_when_cache_is_corrupt(tmp_path, monkeypatch):
    raw = json.loads(FIXTURE.read_text())
    cache = JsonCache(cache_dir=tmp_path)
    (tmp_path / f"{CACHE_KEY}.json").write_text('[{"hostname": "trunc"')
    monkeypatch.setattr(mullvad, "_fetch_sync", lambda *a, **kw: raw)
    assert len(await MullvadProvider().fetch_relays(cache)) == len(raw)
    assert cache.load(CACHE_KEY) == raw


def test_relays_get_city_coordinates():
    """`/www/relays/all/` publishes no latitude or longitude, so position has
    to come from the city table built out of Mullvad's own location list."""
    de = next(r for r in _relays() if r.hostname == "de-ber-wg-001")
    assert de.latitude is not None and de.longitude is not None
    assert de.metadata["geo_precision"] == GEO_PRECISION_CITY
    assert 52.0 < de.latitude < 53.0
    assert 13.0 < de.longitude < 14.0


def test_comma_qualified_city_names_resolve():
    us = next(r for r in _relays() if r.hostname == "us-atl-wg-001")
    assert us.city == "Atlanta, GA"
    assert us.metadata["geo_precision"] == GEO_PRECISION_CITY


def test_every_fixture_relay_is_positioned():
    assert all(r.latitude is not None for r in _relays())
