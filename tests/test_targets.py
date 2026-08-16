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


def test_unroutable_addresses_are_not_probeable():
    """Provider metadata is not always about the public internet: Mullvad's
    SOCKS5 names resolve into 10.124.0.0/16, and probing those would scan the
    user's own network rather than a relay."""
    from nearest_exit.targets import is_probeable_address

    for addr in ("10.124.0.62", "127.0.0.1", "192.168.1.1", "172.16.0.1",
                 "169.254.1.1", "0.0.0.0", "224.0.0.1"):
        assert not is_probeable_address(addr), addr


def test_public_and_documentation_addresses_stay_probeable():
    from nearest_exit.targets import is_probeable_address

    # Real relay addresses, plus the TEST-NET ranges the suite uses as stand-ins.
    for addr in ("193.32.248.66", "8.8.8.8", "192.0.2.1", "198.51.100.7",
                 "203.0.113.5"):
        assert is_probeable_address(addr), addr


def test_hostnames_pass_until_they_are_resolved():
    from nearest_exit.targets import is_probeable_address

    assert is_probeable_address("de-ber-wg-001.relays.mullvad.net")
