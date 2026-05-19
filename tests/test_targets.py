import json
from pathlib import Path

from nearest_exit.providers.airvpn import normalize as normalize_airvpn
from nearest_exit.providers.pia import normalize as normalize_pia
from nearest_exit.providers.pia import parse_payload as parse_pia
from nearest_exit.targets import relay_entry_ips, socks5_target, tcp_fallback_targets

FIXTURES = Path(__file__).parent / "fixtures"


def test_airvpn_tcp_fallback_targets_all_entry_ips():
    payload = json.loads((FIXTURES / "airvpn_status.json").read_text())
    relay = normalize_airvpn(payload)[0]

    targets = tcp_fallback_targets(relay)

    assert [t.host for t in targets] == relay.metadata["entry_ipv4_all"]
    assert {t.port for t in targets} == {443}
    assert {t.kind for t in targets} == {"tcp"}


def test_pia_socks5_target_uses_service_ip_and_port():
    payload = parse_pia((FIXTURES / "pia_servers_v6.txt").read_text())
    relay = next(r for r in normalize_pia(payload) if r.id == "us_atlanta")

    target = socks5_target(relay)

    assert target is not None
    assert target.host == "154.21.0.5"
    assert target.port == 1080
    assert target.kind == "socks5"


def test_pia_openvpn_tcp_target_uses_ovpntcp_port():
    payload = parse_pia((FIXTURES / "pia_servers_v6.txt").read_text())
    relay = next(r for r in normalize_pia(payload) if r.id == "us_atlanta")

    targets = tcp_fallback_targets(relay, feature="openvpn")

    assert len(targets) == 1
    assert targets[0].host == "154.21.0.1"
    assert targets[0].port == 80


def test_relay_entry_ips_falls_back_to_canonical_ipv4():
    payload = parse_pia((FIXTURES / "pia_servers_v6.txt").read_text())
    relay = next(r for r in normalize_pia(payload) if r.id == "de_berlin")

    assert relay_entry_ips(relay) == [relay.ipv4]
