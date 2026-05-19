import asyncio
import json
from dataclasses import replace

from nearest_exit import cli
from nearest_exit.config import Config
from nearest_exit.geo import GeoContext
from nearest_exit.models import ProbeResult, Relay


def _relay(provider: str, hostname: str, rtt: float) -> tuple[Relay, ProbeResult]:
    relay = Relay(
        provider=provider,
        id=hostname,
        hostname=hostname,
        country_code="de",
        country_name="Germany",
        city="Berlin",
        latitude=52.52,
        longitude=13.405,
        ipv4="192.0.2.1",
        protocols=("wireguard",),
        active=True,
    )
    probe = ProbeResult(
        relay_id=hostname,
        probe="icmp",
        target="192.0.2.1",
        success=True,
        rtt_ms=rtt,
        loss=0.0,
        jitter_ms=0.0,
        samples=(rtt,),
    )
    return relay, probe


def test_parser_accepts_scan_provider_all():
    args = cli.build_parser().parse_args(["scan", "--provider", "all"])
    assert args.provider == "all"


def test_scan_provider_all_uses_each_provider(monkeypatch, capsys):
    calls: list[str] = []

    class FakeProvider:
        def __init__(self, name: str):
            self.name = name

        async def fetch_relays(self, cache, refresh=False):
            relay, _probe = _relay(self.name, f"{self.name}-1", 20.0)
            return [relay]

    async def fake_build_provider(name, country, technology, cache):
        calls.append(name)
        return FakeProvider(name)

    async def fake_probe_all(relays, concurrency, count, timeout_s, enable_tcp_fallback=True,
                             show_progress=True, feature=None):
        return [(r, _relay(r.provider, r.hostname, 20.0)[1]) for r in relays]

    monkeypatch.setattr(cli, "detect_vpn", lambda: None)
    monkeypatch.setattr(cli, "build_provider", fake_build_provider)
    monkeypatch.setattr(cli, "probe_all", fake_probe_all)

    args = cli.build_parser().parse_args(["scan", "--provider", "all", "--json"])
    assert asyncio.run(args.func(args)) == 0

    data = json.loads(capsys.readouterr().out)
    assert calls == list(cli.PROVIDER_NAMES)
    assert {row["relay"]["provider"] for row in data} == set(cli.PROVIDER_NAMES)


def test_scan_passes_protocol_to_probe_feature(monkeypatch, capsys):
    seen_features: list[str | None] = []

    class FakeProvider:
        async def fetch_relays(self, cache, refresh=False):
            relay, _probe = _relay("pia", "pia-socks", 20.0)
            return [replace(relay, protocols=("socks5",))]

    async def fake_build_provider(name, country, technology, cache):
        return FakeProvider()

    async def fake_probe_all(relays, concurrency, count, timeout_s, enable_tcp_fallback=True,
                             show_progress=True, feature=None):
        seen_features.append(feature)
        return [(r, _relay(r.provider, r.hostname, 20.0)[1]) for r in relays]

    monkeypatch.setattr(cli, "detect_vpn", lambda: None)
    monkeypatch.setattr(cli, "build_provider", fake_build_provider)
    monkeypatch.setattr(cli, "probe_all", fake_probe_all)

    args = cli.build_parser().parse_args([
        "scan", "--provider", "pia", "--protocol", "socks5", "--json",
    ])
    assert asyncio.run(args.func(args)) == 0

    json.loads(capsys.readouterr().out)
    assert seen_features == ["socks5"]


def test_default_json_output_is_machine_readable(monkeypatch, capsys):
    relay, probe = _relay("mullvad", "de-ber-wg-001", 18.0)
    cfg = Config()
    cfg.providers.order = ["mullvad"]
    cfg.providers.others_allowed = False
    cfg.geo.lookup = "none"

    async def fake_gather_candidates(*args, **kwargs):
        return [(relay, "in-country")], "1 in DE"

    async def fake_provider_full_set(*args, **kwargs):
        return [relay]

    async def fake_probe_all(relays, concurrency, count, timeout_s, enable_tcp_fallback=True,
                             show_progress=True, feature=None):
        return [(relay, probe)]

    monkeypatch.setattr(cli, "load_config", lambda: cfg)
    monkeypatch.setattr(cli, "detect_vpn", lambda: None)
    monkeypatch.setattr(cli, "resolve_geo", lambda *args: GeoContext(
        country_code="de",
        country_name="Germany",
        latitude=52.52,
        longitude=13.405,
        source="test",
    ))
    monkeypatch.setattr(cli, "network_fingerprint", lambda asn, ip: "test-fp")
    monkeypatch.setattr(cli, "recent_winners", lambda fp: {})
    monkeypatch.setattr(cli, "_provider_full_set", fake_provider_full_set)
    monkeypatch.setattr(cli, "_gather_candidates", fake_gather_candidates)
    monkeypatch.setattr(cli, "probe_all", fake_probe_all)
    monkeypatch.setattr(cli, "record_scan", lambda rows, fp: None)

    args = cli.build_parser().parse_args(["--json"])
    assert asyncio.run(args.func(args)) == 0

    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["preferred_providers"] == ["mullvad"]
    assert data["best"][0]["relay"]["hostname"] == "de-ber-wg-001"
    assert "Research:" in captured.err
