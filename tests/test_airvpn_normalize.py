import json
from pathlib import Path

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
