import json
from pathlib import Path

import pytest

from nearest_exit.cache import JsonCache
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


def test_normalize_exposes_socks5_target():
    """SOCKS5 probing only worked for PIA because no other adapter set the
    metadata key `targets.socks5_target` reads."""
    de = next(r for r in _relays() if r.hostname == "de-ber-wg-001")

    assert "socks5" in de.protocols
    target = socks5_target(de)
    assert target is not None
    assert target.host.endswith(".relays.mullvad.net")
    assert target.port == 1080
    assert target.kind == "socks5"


def test_relay_without_socks_endpoint_is_not_advertised_as_socks5():
    bridge = next(r for r in _relays() if r.hostname == "au-syd-br-001")
    assert "socks5" not in bridge.protocols
    assert socks5_target(bridge) is None


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
