import asyncio
import json
from dataclasses import replace

import pytest

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


def test_bare_prefs_shows_config_instead_of_scanning():
    """`prefs` used to inherit the root defaults and run a full internet scan."""
    args = cli.build_parser().parse_args(["prefs"])
    assert args.func is cli.cmd_prefs_show
    assert args._async is False


@pytest.mark.parametrize(
    "argv",
    [
        ["scan", "--concurrency", "0"],
        ["scan", "--concurrency", "-1"],
        ["scan", "--count", "0"],
        ["scan", "--timeout", "0"],
        ["scan", "--top", "0"],
        ["--best", "0"],
        ["--alts", "-1"],
    ],
)
def test_parser_rejects_out_of_range_numbers(argv):
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(argv)


def test_probe_all_clamps_zero_concurrency(monkeypatch):
    """asyncio.Semaphore(0) never releases, so this used to hang forever."""
    relay, probe = _relay("mullvad", "de-ber-wg-001", 20.0)

    async def fake_probe_one(r, count, timeout_s, enable_tcp_fallback, feature=None):
        return probe

    monkeypatch.setattr(cli, "probe_one", fake_probe_one)

    async def run():
        return await asyncio.wait_for(
            cli.probe_all([relay], concurrency=0, count=1, timeout_s=0.1),
            timeout=5,
        )

    pairs = asyncio.run(run())
    assert [p for _r, p in pairs] == [probe]


def _spread(count_per_country: int = 3) -> list[Relay]:
    return [
        Relay(
            provider="mullvad",
            id=f"{cc}-{i}",
            hostname=f"{cc}-wg-{i:03d}",
            country_code=cc,
            country_name=cc.upper(),
            city="City",
            latitude=None,
            longitude=None,
            ipv4=f"192.0.2.{i}",
            protocols=("wireguard",),
            active=True,
        )
        for cc in ("de", "us", "jp", "au")
        for i in range(1, count_per_country + 1)
    ]


def _no_geo() -> GeoContext:
    return GeoContext(
        country_code=None, country_name=None,
        latitude=None, longitude=None, source="none",
    )


def test_gather_candidates_falls_back_when_location_is_unknown(monkeypatch):
    """With no country and no coords the default flow selected nothing and
    exited 1, despite having a full relay list already in hand."""
    relays = _spread()

    async def fake_full_set(name, cache, target_country_id=None):
        return relays

    monkeypatch.setattr(cli, "_provider_full_set", fake_full_set)

    selected, note = asyncio.run(
        cli._gather_candidates(
            "mullvad", None, _no_geo(), Config(), None,
            centroids={}, nearby_ccs=[],
        )
    )

    assert selected, "expected candidates despite unknown location"
    assert {tag for _r, tag in selected} == {"sampled"}
    assert "location unknown" in note
    # Spread across countries rather than taking the alphabetically first ones.
    assert {r.country_code for r, _tag in selected} == {"de", "us", "jp", "au"}


def test_gather_candidates_uses_coords_when_country_is_unknown(monkeypatch):
    relays = [
        replace(r, latitude=52.52, longitude=13.405) if r.country_code == "de"
        else replace(r, latitude=-33.87, longitude=151.21)
        for r in _spread()
    ]

    async def fake_full_set(name, cache, target_country_id=None):
        return relays

    monkeypatch.setattr(cli, "_provider_full_set", fake_full_set)

    geo = GeoContext(
        country_code=None, country_name=None,
        latitude=52.5, longitude=13.4, source="coords",
    )
    selected, note = asyncio.run(
        cli._gather_candidates(
            "mullvad", None, geo, Config(), None, centroids={}, nearby_ccs=[],
        )
    )

    assert "country unknown" in note
    assert {tag for _r, tag in selected} == {"nearest"}
    # Distance still ranks even without a country, so Berlin comes first.
    assert [r.country_code for r, _tag in selected][:3] == ["de", "de", "de"]


def test_sample_across_countries_is_round_robin_and_deterministic():
    relays = _spread(count_per_country=3)
    picked = cli._sample_across_countries(relays, k=6)

    assert len(picked) == 6
    assert [r.country_code for r in picked] == ["au", "de", "jp", "us", "au", "de"]
    assert cli._sample_across_countries(relays, k=6) == picked
    assert cli._sample_across_countries(relays, k=0) == []
    assert len(cli._sample_across_countries(relays, k=999)) == len(relays)


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
