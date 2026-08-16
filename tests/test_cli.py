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

    async def fake_probe_one(r, count, timeout_s, enable_tcp_fallback,
                             feature=None, limiter=None):
        return probe

    monkeypatch.setattr(cli, "probe_one", fake_probe_one)

    async def run():
        return await asyncio.wait_for(
            cli.probe_all([relay], concurrency=0, count=1, timeout_s=0.1),
            timeout=5,
        )

    pairs = asyncio.run(run())
    assert [p for _r, p in pairs] == [probe]


def test_best_probe_prefers_clean_target_over_faster_lossy_one():
    """Ordering on raw RTT picked a 10ms target dropping half its packets."""
    fast_lossy = ProbeResult(
        relay_id="r", probe="icmp", target="192.0.2.1", success=True,
        rtt_ms=10.0, loss=0.5, jitter_ms=1.0, samples=(10.0, 10.0),
    )
    slow_clean = ProbeResult(
        relay_id="r", probe="icmp", target="192.0.2.2", success=True,
        rtt_ms=20.0, loss=0.0, jitter_ms=1.0, samples=(20.0,) * 4,
    )
    assert cli._best_probe([fast_lossy, slow_clean]).target == "192.0.2.2"
    assert cli._best_probe([slow_clean, fast_lossy]).target == "192.0.2.2"


def test_best_probe_prefers_any_success_over_failure():
    dead = ProbeResult(
        relay_id="r", probe="icmp", target="192.0.2.1", success=False,
        rtt_ms=None, loss=1.0, jitter_ms=None, samples=(), error="timeout",
    )
    alive = ProbeResult(
        relay_id="r", probe="icmp", target="192.0.2.2", success=True,
        rtt_ms=400.0, loss=0.25, jitter_ms=50.0, samples=(400.0,) * 3,
    )
    assert cli._best_probe([dead, alive]).target == "192.0.2.2"


def test_probe_one_probes_entry_ips_concurrently(monkeypatch):
    """AirVPN publishes up to four entry IPs; these ran one after another."""
    inflight = 0
    peak = 0

    async def fake_icmp(relay_id, ip, count, timeout_s):
        nonlocal inflight, peak
        inflight += 1
        peak = max(peak, inflight)
        await asyncio.sleep(0.01)
        inflight -= 1
        return ProbeResult(
            relay_id=relay_id, probe="icmp", target=ip, success=True,
            rtt_ms=20.0, loss=0.0, jitter_ms=0.0, samples=(20.0,) * count,
        )

    monkeypatch.setattr(cli, "icmp_probe", fake_icmp)
    base, _probe = _relay("airvpn", "air-1", 20.0)
    relay = replace(base, metadata={
        "entry_ipv4_all": [f"192.0.2.{i}" for i in range(1, 5)],
    })

    result = asyncio.run(
        cli.probe_one(relay, count=3, timeout_s=1.0, enable_tcp_fallback=False)
    )

    assert peak == 4, f"entry IPs probed {peak} at a time, expected 4"
    assert result.success


def _scan_penalty_fixture(monkeypatch):
    cfg = Config()
    cfg.providers.penalties_ms = {"mullvad": 0.0, "nordvpn": 30.0}
    rtts = {"mullvad": 30.0, "nordvpn": 20.0}

    class FakeProvider:
        def __init__(self, name: str):
            self.name = name

        async def fetch_relays(self, cache, refresh=False):
            if self.name not in rtts:
                return []
            return [_relay(self.name, f"{self.name}-1", 0.0)[0]]

    async def fake_build_provider(name, country, technology, cache):
        return FakeProvider(name)

    async def fake_probe_all(relays, concurrency, count, timeout_s,
                             enable_tcp_fallback=True, show_progress=True, feature=None):
        return [
            (r, _relay(r.provider, r.hostname, rtts[r.provider])[1]) for r in relays
        ]

    monkeypatch.setattr(cli, "load_config", lambda: cfg)
    monkeypatch.setattr(cli, "detect_vpn", lambda: None)
    monkeypatch.setattr(cli, "build_provider", fake_build_provider)
    monkeypatch.setattr(cli, "probe_all", fake_probe_all)


def test_scan_ranks_on_measurement_alone_by_default(monkeypatch, capsys):
    """`scan` is the audit trail: it must always be able to show what the
    network said, independent of any configured preference."""
    _scan_penalty_fixture(monkeypatch)

    args = cli.build_parser().parse_args(["scan", "--provider", "all", "--json"])
    assert asyncio.run(args.func(args)) == 0

    data = json.loads(capsys.readouterr().out)
    assert data[0]["relay"]["provider"] == "nordvpn"
    assert data[0]["measured_cost_ms"] == data[0]["effective_cost_ms"] == 20.0


def test_scan_applies_provider_penalties_on_request(monkeypatch, capsys):
    _scan_penalty_fixture(monkeypatch)

    args = cli.build_parser().parse_args(
        ["scan", "--provider", "all", "--json", "--preferences"]
    )
    assert asyncio.run(args.func(args)) == 0

    captured = capsys.readouterr()
    data = json.loads(captured.out)
    # nordvpn measured faster (20ms vs 30ms) but carries a 30ms penalty.
    assert data[0]["relay"]["provider"] == "mullvad"
    assert data[0]["measured_cost_ms"] == 30.0
    assert data[1]["measured_cost_ms"] == 20.0
    assert data[1]["effective_cost_ms"] == 50.0
    assert "applying provider preferences" in captured.err


def test_scan_geofilter_honours_lookup_override(monkeypatch, capsys):
    """--geofilter was hardcoded to ipinfo, so `--lookup none` still made a
    network call and manual coordinates were ignored."""
    seen: list[tuple] = []

    def fake_resolve_geo(lookup, country, coords, mmdb):
        seen.append((lookup, country, coords))
        return GeoContext(
            country_code="de", country_name="Germany",
            latitude=52.52, longitude=13.405, source="override",
        )

    class FakeProvider:
        async def fetch_relays(self, cache, refresh=False):
            return _spread()

    async def fake_build_provider(name, country, technology, cache):
        return FakeProvider()

    async def fake_probe_all(relays, concurrency, count, timeout_s,
                             enable_tcp_fallback=True, show_progress=True, feature=None):
        return [(r, _relay(r.provider, r.hostname, 20.0)[1]) for r in relays]

    monkeypatch.setattr(cli, "load_config", Config)
    monkeypatch.setattr(cli, "detect_vpn", lambda: None)
    monkeypatch.setattr(cli, "resolve_geo", fake_resolve_geo)
    monkeypatch.setattr(cli, "build_provider", fake_build_provider)
    monkeypatch.setattr(cli, "probe_all", fake_probe_all)

    args = cli.build_parser().parse_args(
        ["--lookup", "none", "--coords", "52.5", "13.4", "scan", "--geofilter", "2", "--json"]
    )
    assert asyncio.run(args.func(args)) == 0

    assert seen == [("none", None, (52.5, 13.4))]
    assert len(json.loads(capsys.readouterr().out)) == 2


def test_scan_geofilter_without_a_location_probes_everything(monkeypatch, capsys):
    def fake_resolve_geo(lookup, country, coords, mmdb):
        return GeoContext(source="none")

    class FakeProvider:
        async def fetch_relays(self, cache, refresh=False):
            return _spread()

    async def fake_build_provider(name, country, technology, cache):
        return FakeProvider()

    async def fake_probe_all(relays, concurrency, count, timeout_s,
                             enable_tcp_fallback=True, show_progress=True, feature=None):
        return [(r, _relay(r.provider, r.hostname, 20.0)[1]) for r in relays]

    monkeypatch.setattr(cli, "load_config", Config)
    monkeypatch.setattr(cli, "detect_vpn", lambda: None)
    monkeypatch.setattr(cli, "resolve_geo", fake_resolve_geo)
    monkeypatch.setattr(cli, "build_provider", fake_build_provider)
    monkeypatch.setattr(cli, "probe_all", fake_probe_all)

    args = cli.build_parser().parse_args(
        ["scan", "--geofilter", "2", "--json", "--top", "99"]
    )
    assert asyncio.run(args.func(args)) == 0

    captured = capsys.readouterr()
    assert "--geofilter needs a location" in captured.err
    assert len(json.loads(captured.out)) == len(_spread())


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
            nearby_ccs=[],
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
            "mullvad", None, geo, Config(), None, nearby_ccs=[],
        )
    )

    assert "country unknown" in note
    assert {tag for _r, tag in selected} == {"nearest"}
    # Distance still ranks even without a country, so Berlin comes first.
    assert [r.country_code for r, _tag in selected][:3] == ["de", "de", "de"]


@pytest.mark.parametrize(
    "argv,expected",
    [
        ([], None),
        (["--here"], cli.SCOPE_HERE),
        (["--nearby"], cli.SCOPE_NEARBY),
        (["--global"], cli.SCOPE_GLOBAL),
        (["--scope", "global"], cli.SCOPE_GLOBAL),
    ],
)
def test_scope_flags(argv, expected):
    """PLAN documented --here/--nearby/--global as scope flags; --here used to
    be a country override instead, and none of the three existed."""
    assert cli.build_parser().parse_args(argv).scope == expected


def test_country_override_is_its_own_flag():
    assert cli.build_parser().parse_args(["--country", "YE"]).country == "YE"


def _gather(scope, nearby_ccs, monkeypatch, relays):
    async def fake_full_set(name, cache, target_country_id=None):
        return relays

    monkeypatch.setattr(cli, "_provider_full_set", fake_full_set)
    geo = GeoContext(
        country_code="de", country_name="Germany",
        latitude=52.52, longitude=13.405, source="test",
    )
    return asyncio.run(
        cli._gather_candidates(
            "mullvad", "de", geo, Config(), None,
            nearby_ccs=nearby_ccs, scope=scope,
        )
    )


def test_scope_here_stays_in_country(monkeypatch):
    selected, note = _gather(cli.SCOPE_HERE, ["us", "jp"], monkeypatch, _spread())

    assert {r.country_code for r, _tag in selected} == {"de"}
    assert "nearby" not in note


def test_scope_nearby_samples_neighbours(monkeypatch):
    selected, _note = _gather(cli.SCOPE_NEARBY, ["us", "jp"], monkeypatch, _spread())

    assert {r.country_code for r, _tag in selected} == {"de", "us", "jp"}
    assert {tag for _r, tag in selected} == {"in-country", "neighbor:US", "neighbor:JP"}


def test_scope_global_reaches_every_country(monkeypatch):
    selected, note = _gather(cli.SCOPE_GLOBAL, ["us"], monkeypatch, _spread())

    assert {r.country_code for r, _tag in selected} == {"de", "us", "jp", "au"}
    assert "worldwide" in note
    # No relay is selected twice, whichever branch reached it first.
    keys = [(r.provider, r.id) for r, _tag in selected]
    assert len(keys) == len(set(keys))


def test_scan_top_defaults_to_config(monkeypatch, capsys):
    cfg = Config()
    cfg.defaults.top = 2

    class FakeProvider:
        async def fetch_relays(self, cache, refresh=False):
            return _spread()

    async def fake_build_provider(name, country, technology, cache):
        return FakeProvider()

    async def fake_probe_all(relays, concurrency, count, timeout_s,
                             enable_tcp_fallback=True, show_progress=True, feature=None):
        return [(r, _relay(r.provider, r.hostname, 20.0)[1]) for r in relays]

    monkeypatch.setattr(cli, "load_config", lambda: cfg)
    monkeypatch.setattr(cli, "detect_vpn", lambda: None)
    monkeypatch.setattr(cli, "build_provider", fake_build_provider)
    monkeypatch.setattr(cli, "probe_all", fake_probe_all)

    args = cli.build_parser().parse_args(["scan", "--json"])
    assert asyncio.run(args.func(args)) == 0
    assert len(json.loads(capsys.readouterr().out)) == 2


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

    args = cli.build_parser().parse_args(["scan", "--provider", "all", "--json", "--top", "10"])
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


def _stub_default_flow(monkeypatch, cfg, relay, probe):
    async def fake_gather_candidates(*args, **kwargs):
        return [(relay, "in-country")], "1 in DE"

    async def fake_provider_full_set(*args, **kwargs):
        return [relay]

    async def fake_probe_all(relays, concurrency, count, timeout_s,
                             enable_tcp_fallback=True, show_progress=True, feature=None):
        return [(relay, probe)]

    monkeypatch.setattr(cli, "load_config", lambda: cfg)
    monkeypatch.setattr(cli, "detect_vpn", lambda: None)
    monkeypatch.setattr(cli, "resolve_geo", lambda *args: GeoContext(
        country_code="de", country_name="Germany",
        latitude=52.52, longitude=13.405, source="test",
    ))
    monkeypatch.setattr(cli, "network_fingerprint", lambda asn, ip: "test-fp")
    monkeypatch.setattr(cli, "recent_winners", lambda fp: {})
    monkeypatch.setattr(cli, "_provider_full_set", fake_provider_full_set)
    monkeypatch.setattr(cli, "_gather_candidates", fake_gather_candidates)
    monkeypatch.setattr(cli, "probe_all", fake_probe_all)
    monkeypatch.setattr(cli, "record_scan", lambda rows, fp: None)


def test_human_output_keeps_research_chatter_off_stdout(monkeypatch, capsys):
    """`nearest-exit | tail -1` used to return research narration, not a relay."""
    relay, probe = _relay("mullvad", "de-ber-wg-001", 18.0)
    cfg = Config()
    cfg.geo.lookup = "none"
    _stub_default_flow(monkeypatch, cfg, relay, probe)

    args = cli.build_parser().parse_args([])
    assert asyncio.run(args.func(args)) == 0

    captured = capsys.readouterr()
    assert "Research:" in captured.err
    assert "You:" in captured.err
    assert "Research:" not in captured.out
    assert "You:" not in captured.out
    for line in captured.out.splitlines():
        assert line == "" or line.startswith(("Best", "Alternatives", "Nearby", "  ")), line


def test_why_explains_how_the_ranked_number_was_built(monkeypatch, capsys):
    relay, probe = _relay("mullvad", "de-ber-wg-001", 18.0)
    cfg = Config()
    cfg.geo.lookup = "none"
    cfg.providers.penalties_ms = {"mullvad": 7.0}
    _stub_default_flow(monkeypatch, cfg, relay, probe)

    args = cli.build_parser().parse_args(["--why"])
    assert asyncio.run(args.func(args)) == 0

    out = capsys.readouterr().out
    assert "median RTT 18.0ms" in out
    assert "provider preference +7.0ms" in out
    assert "ranked at 25.0ms" in out
    assert "→ ranked 25.0ms (+7.0)" in out


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


def test_filter_keeps_relays_that_doh_could_still_resolve():
    """Dropping every relay without an ipv4 meant the DoH fallback in
    `_ensure_ipv4` could never fire on the main path."""
    base, _p = _relay("mullvad", "de-ber-wg-001", 20.0)
    resolvable = replace(base, ipv4=None, hostname="de-ber-wg-001.relays.mullvad.net")
    opaque = replace(base, ipv4=None, hostname="Adhara")

    kept = cli.filter_relays(
        [resolvable, opaque], country=None, city=None, protocol=None,
        active_only=False, owned=None,
    )

    assert [r.hostname for r in kept] == ["de-ber-wg-001.relays.mullvad.net"]


def test_sticky_history_is_off_unless_asked_for(monkeypatch):
    """A relay winning here before is a preference for stability, not a
    measurement, so it must not shape the default answer."""
    relay, probe = _relay("mullvad", "de-ber-wg-001", 18.0)
    consulted: list[str] = []

    cfg = Config()
    cfg.geo.lookup = "none"
    _stub_default_flow(monkeypatch, cfg, relay, probe)
    monkeypatch.setattr(cli, "recent_winners", lambda fp: consulted.append(fp) or {})

    args = cli.build_parser().parse_args(["--json"])
    assert asyncio.run(args.func(args)) == 0
    assert consulted == []

    cfg.history.sticky = True
    assert asyncio.run(args.func(args)) == 0
    assert consulted == ["test-fp"]


def test_history_records_the_measured_order_not_the_recommended_one(monkeypatch):
    """Writing the policy winner back made preference self-reinforcing: it
    wins because it is preferred, is recorded as the winner, and then gets a
    head start for having won."""
    preferred, slow = _relay("nordvpn", "nord-1", 30.0)
    other, fast = _relay("mullvad", "mull-1", 20.0)

    cfg = Config()
    cfg.geo.lookup = "none"
    cfg.providers.order = ["nordvpn"]
    cfg.providers.penalties_ms = {"nordvpn": 0.0, "mullvad": 40.0}

    recorded: list[list[dict]] = []

    async def fake_gather(*args, **kwargs):
        return [(preferred, "in-country"), (other, "in-country")], "2 in DE"

    async def fake_full_set(*args, **kwargs):
        return [preferred, other]

    async def fake_probe_all(relays, concurrency, count, timeout_s,
                             enable_tcp_fallback=True, show_progress=True, feature=None):
        return [(preferred, slow), (other, fast)]

    monkeypatch.setattr(cli, "load_config", lambda: cfg)
    monkeypatch.setattr(cli, "detect_vpn", lambda: None)
    monkeypatch.setattr(cli, "resolve_geo", lambda *a: GeoContext(
        country_code="de", country_name="Germany",
        latitude=52.52, longitude=13.405, source="test",
    ))
    monkeypatch.setattr(cli, "network_fingerprint", lambda asn, ip: "fp")
    monkeypatch.setattr(cli, "recent_winners", lambda fp: {})
    monkeypatch.setattr(cli, "_provider_full_set", fake_full_set)
    monkeypatch.setattr(cli, "_gather_candidates", fake_gather)
    monkeypatch.setattr(cli, "probe_all", fake_probe_all)
    monkeypatch.setattr(cli, "record_scan", lambda rows, fp: recorded.append(rows))

    args = cli.build_parser().parse_args(["--json"])
    assert asyncio.run(args.func(args)) == 0

    rows = recorded[0]
    # Preference makes nordvpn the recommendation, but mullvad was faster.
    assert rows[0]["provider"] == "mullvad"
    assert rows[0]["rank"] == 1
