import json
from pathlib import Path

import pytest

from nearest_exit.cache import JsonCache
from nearest_exit.providers import mullvad
from nearest_exit.providers.mullvad import CACHE_KEY, MullvadProvider, normalize

FIXTURE = Path(__file__).parent / "fixtures" / "mullvad_sample.json"


def test_normalize_basic_fields():
    raw = json.loads(FIXTURE.read_text())
    relays = normalize(raw)
    assert len(relays) == 3

    se = next(r for r in relays if r.hostname == "se-sto-wg-001")
    assert se.provider == "mullvad"
    assert se.country_code == "se"
    assert se.country_name == "Sweden"
    assert se.city == "Stockholm"
    assert se.ipv4 == "185.213.154.66"
    assert se.ipv6 == "2a03:1b20:5:f011::a09f"
    assert se.protocols == ("wireguard",)
    assert se.active is True
    assert se.owned is True
    assert se.latitude == 59.3293


def test_normalize_preserves_raw_metadata():
    raw = json.loads(FIXTURE.read_text())
    relays = normalize(raw)
    de = next(r for r in relays if r.hostname == "de-fra-wg-401")
    assert de.metadata["network_port_speed"] == 10
    assert de.metadata["provider"] == "31173"


async def test_fetch_uses_cache_when_fresh(tmp_path, monkeypatch):
    raw = json.loads(FIXTURE.read_text())
    cache = JsonCache(cache_dir=tmp_path)
    cache.save(CACHE_KEY, raw)
    monkeypatch.setattr(
        mullvad, "_fetch_sync",
        lambda *a, **kw: pytest.fail("network hit despite fresh cache"),
    )
    relays = await MullvadProvider().fetch_relays(cache)
    assert len(relays) == 3


async def test_fetch_refetches_when_cache_is_corrupt(tmp_path, monkeypatch):
    raw = json.loads(FIXTURE.read_text())
    cache = JsonCache(cache_dir=tmp_path)
    (tmp_path / f"{CACHE_KEY}.json").write_text('[{"hostname": "trunc"')
    monkeypatch.setattr(mullvad, "_fetch_sync", lambda *a, **kw: raw)
    relays = await MullvadProvider().fetch_relays(cache)
    assert len(relays) == 3
    assert cache.load(CACHE_KEY) == raw


def test_normalize_handles_inactive():
    raw = json.loads(FIXTURE.read_text())
    relays = normalize(raw)
    inactive = next(r for r in relays if r.hostname == "us-nyc-ovpn-101")
    assert inactive.active is False
    assert inactive.protocols == ("openvpn",)
