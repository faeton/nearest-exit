from pathlib import Path

from nearest_exit.providers.pia import normalize, parse_payload

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
