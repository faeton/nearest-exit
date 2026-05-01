from __future__ import annotations

import argparse
import asyncio
import json
import math
import sys
from dataclasses import asdict

from .cache import JsonCache, default_cache_dir
from .config import Config, default_config_path, load_config, write_default_config
from .countries import merged_centroids, nearest_countries
from .diagnostics import detect_vpn, ping_available
from .doh import resolve_a
from .geo import GeoContext, lookup_ipinfo, resolve_geo
from .geofilter import haversine_km, top_k_by_distance
from .history import (
    network_fingerprint,
    record_scan,
    recent_winners,
    sticky_bonus,
)
from .models import ProbeResult, Relay
from .probes.icmp import icmp_probe
from .probes.tcp import tcp_probe
from .rounds import flappy, merge_rounds
from .providers.airvpn import AirVPNProvider
from .providers.mullvad import MullvadProvider
from .providers.nordvpn import NordVPNProvider, country_code_to_id, fetch_countries
from .scoring import rank


def make_provider(name: str, country: str | None, technology: str | None,
                  cache: JsonCache):
    if name == "mullvad":
        return MullvadProvider(), None
    if name == "nordvpn":
        country_id = None
        if country:
            countries = asyncio.get_event_loop().run_until_complete(
                fetch_countries(cache)
            ) if False else None  # placeholder; resolve in async path
            _ = countries
        return NordVPNProvider(country_id=None, technology=technology), country
    raise ValueError(f"unknown provider {name}")


PROVIDER_NAMES = ("mullvad", "nordvpn", "airvpn")


async def build_provider(name: str, country: str | None, technology: str | None,
                          cache: JsonCache):
    if name == "mullvad":
        return MullvadProvider()
    if name == "nordvpn":
        country_id = None
        if country:
            countries = await fetch_countries(cache)
            country_id = country_code_to_id(countries, country)
            if country_id is None:
                print(
                    f"WARNING: NordVPN has no country matching '{country}'.",
                    file=sys.stderr,
                )
        # default WireGuard if no technology specified
        return NordVPNProvider(country_id=country_id, technology=technology)
    if name == "airvpn":
        return AirVPNProvider()
    raise ValueError(f"unknown provider {name}")


def filter_relays(
    relays: list[Relay],
    country: str | None,
    city: str | None,
    protocol: str | None,
    active_only: bool,
    owned: bool | None,
) -> list[Relay]:
    out = []
    for r in relays:
        if country:
            cc = (r.country_code or "").lower()
            cn = (r.country_name or "").lower()
            q = country.lower()
            if q != cc and q != cn:
                continue
        if city and (r.city or "").lower() != city.lower():
            continue
        if protocol and protocol.lower() not in (p.lower() for p in r.protocols):
            continue
        if active_only and r.active is False:
            continue
        if owned is not None and r.owned != owned:
            continue
        if not r.ipv4:
            continue
        out.append(r)
    return out


async def _ensure_ipv4(relay: Relay) -> str | None:
    """Return relay.ipv4, or resolve hostname via DoH if missing."""
    if relay.ipv4:
        return relay.ipv4
    if not relay.hostname:
        return None
    ips = await asyncio.to_thread(resolve_a, relay.hostname)
    return ips[0] if ips else None


async def probe_one(relay: Relay, count: int, timeout_s: float,
                    enable_tcp_fallback: bool) -> ProbeResult:
    ip = await _ensure_ipv4(relay)
    if not ip:
        return ProbeResult(
            relay_id=relay.id, probe="none", target=relay.hostname,
            success=False, rtt_ms=None, loss=1.0, jitter_ms=None,
            samples=(), error="no IP (DoH failed)",
        )
    icmp = await icmp_probe(relay.id, ip, count=count, timeout_s=timeout_s)
    if icmp.success or not enable_tcp_fallback:
        return icmp
    tcp = await tcp_probe(relay.id, ip, port=443,
                          count=max(2, count - 1), timeout_s=timeout_s)
    return tcp


async def probe_all(
    relays: list[Relay],
    concurrency: int,
    count: int,
    timeout_s: float,
    enable_tcp_fallback: bool = True,
    show_progress: bool = True,
):
    sem = asyncio.Semaphore(concurrency)
    total = len(relays)
    done = 0
    progress = show_progress and sys.stderr.isatty()

    async def run(r: Relay):
        nonlocal done
        async with sem:
            res = await probe_one(r, count, timeout_s, enable_tcp_fallback)
        done += 1
        if progress:
            print(f"\rprobed {done}/{total}", end="", file=sys.stderr, flush=True)
        return r, res

    pairs = await asyncio.gather(*(run(r) for r in relays))
    if progress:
        print("", file=sys.stderr)
    return list(pairs)


def print_table(ranked, top: int) -> None:
    cols = ("rank", "provider", "server", "country", "city", "protocol",
            "ipv4", "probe", "rtt", "loss", "jitter")
    rows = []
    for i, rr in enumerate(ranked[:top], 1):
        r, p = rr.relay, rr.probe
        rows.append((
            str(i),
            r.provider,
            r.hostname,
            r.country_code or "",
            r.city or "",
            (r.protocols[0] if r.protocols else ""),
            r.ipv4 or "",
            p.probe,
            f"{p.rtt_ms:.1f}ms" if p.rtt_ms is not None else "—",
            f"{p.loss * 100:.0f}%" if p.loss is not None else "—",
            f"{p.jitter_ms:.1f}ms" if p.jitter_ms is not None else "—",
        ))
    widths = [max(len(c), max((len(r[i]) for r in rows), default=0))
              for i, c in enumerate(cols)]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*cols))
    for r in rows:
        print(fmt.format(*r))


def print_json(ranked, top: int) -> None:
    data = []
    for i, rr in enumerate(ranked[:top], 1):
        d = {
            "rank": i,
            "relay": {k: v for k, v in asdict(rr.relay).items() if k != "metadata"},
            "probe": asdict(rr.probe),
            "reasons": list(rr.reasons),
        }
        data.append(d)
    print(json.dumps(data, indent=2, default=str))


async def cmd_scan(args: argparse.Namespace) -> int:
    cache = JsonCache(ttl_seconds=24 * 3600)

    if vpn := detect_vpn():
        print(
            f"WARNING: default route via {vpn} (looks like a VPN tunnel). "
            f"Disconnect for accurate results.",
            file=sys.stderr,
        )

    provider = await build_provider(
        args.provider, country=args.country, technology=args.technology, cache=cache,
    )
    relays = await provider.fetch_relays(cache, refresh=args.refresh)
    relays = filter_relays(
        relays,
        country=args.country,
        city=args.city,
        protocol=args.protocol,
        active_only=not args.include_inactive,
        owned=args.owned,
    )
    if not relays:
        print("No relays match filters.", file=sys.stderr)
        return 1

    if args.geofilter and args.geofilter > 0 and len(relays) > args.geofilter:
        geo = await asyncio.to_thread(lookup_ipinfo)
        relays = top_k_by_distance(relays, geo.latitude, geo.longitude, k=args.geofilter)
        if args.verbose:
            print(
                f"geofiltered to {len(relays)} nearest "
                f"(from {geo.city}, {(geo.country_code or '?').upper()})",
                file=sys.stderr,
            )

    if args.verbose:
        print(f"probing {len(relays)} relays...", file=sys.stderr)

    pairs = await probe_all(
        relays,
        concurrency=args.concurrency,
        count=args.count,
        timeout_s=args.timeout,
        enable_tcp_fallback=not args.no_tcp_fallback,
    )
    ranked = rank(pairs)

    if not any(rr.probe.success for rr in ranked):
        print(
            "WARNING: no relays replied (ICMP and TCP both failed). "
            "Network may block all outbound probes.",
            file=sys.stderr,
        )

    if args.json:
        print_json(ranked, args.top)
    else:
        print_table(ranked, args.top)
    return 0


def _fmt_relay_line(r: Relay, p: ProbeResult, source: str = "") -> str:
    proto = r.protocols[0] if r.protocols else ""
    cc = (r.country_code or "").upper()
    rtt = f"{p.rtt_ms:.1f}ms" if p.rtt_ms is not None else "—".ljust(7)
    if p.jitter_ms is not None and p.jitter_ms >= 1.0:
        rtt = f"{rtt} ±{p.jitter_ms:.0f}ms"
    bits = [
        f"{r.provider:<8}",
        f"{r.hostname:<26}",
        f"[{cc:<2}]",
        f"{proto:<10}",
        rtt,
        f"loss {(p.loss or 0) * 100:.0f}%",
    ]
    if r.load is not None:
        bits.append(f"load {r.load:.0f}%")
    if source:
        bits.append(f"({source})")
    return "  " + "  ".join(bits)


async def _provider_full_set(
    name: str, cache: JsonCache, target_country_id: int | None = None,
) -> list[Relay]:
    """Fetch a provider's relay set with sensible coverage for centroid use.

    For Mullvad/AirVPN this is just the cached full list. For NordVPN we
    request a larger limit so the result covers many countries, which is
    needed to compute reliable country centroids and find neighbors.
    """
    if name == "mullvad":
        return await MullvadProvider().fetch_relays(cache)
    if name == "airvpn":
        return await AirVPNProvider().fetch_relays(cache)
    if name == "nordvpn":
        return await NordVPNProvider(country_id=target_country_id, limit=500).fetch_relays(cache)
    return []


async def _nordvpn_for_country(cc: str, cache: JsonCache, limit: int = 30) -> list[Relay]:
    """NordVPN per-country fetch when the global cached set lacks this country."""
    countries = await fetch_countries(cache)
    cid = country_code_to_id(countries, cc)
    if cid is None:
        return []
    return await NordVPNProvider(country_id=cid, limit=limit).fetch_relays(cache)


async def _gather_candidates(
    name: str,
    country_filter: str | None,
    geo: GeoContext,
    cfg,
    cache: JsonCache,
    centroids: dict[str, tuple[float, float]],
    nearby_ccs: list[str],
    in_country_k: int = 60,
    relays_per_nearby_country: int = 1,
    fallback_neighbor_k: int = 8,
) -> tuple[list[tuple[Relay, str]], str]:
    """Return (list of (relay, source-tag), human-readable note).

    `nearby_ccs` is a pre-computed list of the geographically-nearest *other*
    countries (computed from a centroid table built from union of provider
    relay coords). For each of those countries, we sample
    `relays_per_nearby_country` nearest relays from this provider — querying
    NordVPN per-country if the global cached set doesn't include that country.
    """
    detected_cc = (country_filter or "").lower()
    target_country_id = None
    if name == "nordvpn" and detected_cc:
        target_country_id = country_code_to_id(
            await fetch_countries(cache), detected_cc
        )

    all_relays = await _provider_full_set(name, cache, target_country_id)
    all_relays = filter_relays(
        all_relays, country=None, city=None,
        protocol=cfg.defaults.feature, active_only=True, owned=None,
    )
    if not all_relays:
        return ([], "0 anywhere")

    in_country = [r for r in all_relays if (r.country_code or "").lower() == detected_cc]
    by_cc: dict[str, list[Relay]] = {}
    for r in all_relays:
        by_cc.setdefault((r.country_code or "").lower(), []).append(r)

    selected: list[tuple[Relay, str]] = []
    note_parts: list[str] = []

    if in_country:
        picks = top_k_by_distance(
            in_country, geo.latitude, geo.longitude, k=in_country_k
        )
        for r in picks:
            selected.append((r, "in-country"))
        note_parts.append(f"{len(in_country)} in {detected_cc.upper()}")
    elif detected_cc:
        # No relays in detected country: fall back to nearest globally.
        recov = top_k_by_distance(
            all_relays, geo.latitude, geo.longitude, k=fallback_neighbor_k
        )
        for r in recov:
            selected.append((r, "nearest"))
        note_parts.append(f"0 in {detected_cc.upper()} → nearest {len(recov)}")

    # For each nearby country (computed from union centroids), sample relays.
    added_neighbors = 0
    missing_neighbors: list[str] = []
    for cc in nearby_ccs:
        cc_l = cc.lower()
        if cc_l == detected_cc:
            continue
        candidates = by_cc.get(cc_l) or []
        if not candidates and name == "nordvpn":
            extra = await _nordvpn_for_country(cc_l, cache)
            extra = filter_relays(
                extra, country=None, city=None,
                protocol=cfg.defaults.feature, active_only=True, owned=None,
            )
            candidates = extra
        if not candidates:
            missing_neighbors.append(cc_l.upper())
            continue
        picks = top_k_by_distance(
            candidates, geo.latitude, geo.longitude, k=relays_per_nearby_country,
        )
        already = {r.id for r, _ in selected}
        for r in picks:
            if r.id in already:
                continue
            selected.append((r, f"neighbor:{cc_l.upper()}"))
            already.add(r.id)
            added_neighbors += 1

    if added_neighbors:
        note_parts.append(f"+{added_neighbors} from nearby countries")
    if missing_neighbors:
        note_parts.append(f"none in {','.join(missing_neighbors)}")

    return selected, ", ".join(note_parts) if note_parts else "0"


async def cmd_default(args: argparse.Namespace) -> int:
    """Headline action: detect context → preferred providers → best + alternatives + nearby."""
    cfg = load_config()
    cache = JsonCache(ttl_seconds=24 * 3600)

    if vpn := detect_vpn():
        print(
            f"warning: default route via {vpn} (VPN tunnel). "
            f"Disconnect for accurate results.",
            file=sys.stderr,
        )

    override_country = args.here or cfg.geo.country
    override_coords: tuple[float, float] | None = None
    if args.coords:
        override_coords = (float(args.coords[0]), float(args.coords[1]))
    elif cfg.geo.coords:
        override_coords = cfg.geo.coords

    lookup_mode = args.lookup or cfg.geo.lookup
    geo = await asyncio.to_thread(
        resolve_geo,
        lookup_mode,
        override_country,
        override_coords,
        cfg.geo.mmdb_path,
    )

    loc_str = ""
    if geo.city or geo.country_code:
        loc_str = f"{geo.city or '?'}, {(geo.country_code or '?').upper()}"
    elif geo.latitude is not None:
        loc_str = f"({geo.latitude:.2f}, {geo.longitude:.2f})"
    egress_str = ""
    if geo.ip:
        egress_str = f"egress {geo.ip}"
        if geo.asn:
            egress_str += f" / {geo.asn}"
    bits = [
        b for b in (loc_str, geo.org, egress_str, f"via {vpn}" if vpn else "") if b
    ]
    if bits:
        print(f"You: {' — '.join(bits)}  [geo: {geo.source}]")
    else:
        print(f"You: location unknown  [geo: {geo.source}]")

    country_filter = args.country or geo.country_code

    pref_order = [p for p in cfg.providers.order if p in PROVIDER_NAMES]
    if not pref_order:
        pref_order = list(PROVIDER_NAMES)

    fp = network_fingerprint(geo.asn, geo.ip)
    winners = recent_winners(fp)

    # Pre-fetch each preferred provider's full relay set in parallel so we
    # can build a country-centroid map covering all preferred providers
    # before we pick neighbors.
    print(f"\nResearch: {len(pref_order)} preferred providers, "
          f"location {loc_str or 'unknown'}")
    if cfg.defaults.feature:
        print(f"  feature filter: {cfg.defaults.feature}")

    print("  fetching provider metadata…", file=sys.stderr)
    fetched_sets: dict[str, list[Relay]] = {}
    for name in pref_order:
        try:
            target_cid = None
            if name == "nordvpn" and country_filter:
                target_cid = country_code_to_id(
                    await fetch_countries(cache), country_filter
                )
            fetched_sets[name] = await _provider_full_set(name, cache, target_cid)
        except Exception as e:
            print(f"    {name}: fetch error: {e}", file=sys.stderr)
            fetched_sets[name] = []

    union_relays: list[Relay] = [r for rs in fetched_sets.values() for r in rs]
    centroids = merged_centroids(union_relays)

    nearby_ccs = []
    if geo.latitude is not None and geo.longitude is not None:
        nearby_ccs = [
            cc for cc, _d in nearest_countries(
                centroids, geo.latitude, geo.longitude, k=6,
                exclude={(country_filter or "").lower()},
            )
        ]
    if nearby_ccs:
        print(f"  nearest countries by centroid: {', '.join(c.upper() for c in nearby_ccs)}")

    all_pairs: list[tuple[Relay, ProbeResult, str]] = []
    for name in pref_order:
        try:
            tagged, note = await _gather_candidates(
                name, country_filter, geo, cfg, cache,
                centroids=centroids, nearby_ccs=nearby_ccs,
                in_country_k=60, relays_per_nearby_country=1,
                fallback_neighbor_k=8,
            )
            print(f"  {name:<8} {note}")
            if not tagged:
                continue
            tag_by_id = {r.id: tag for r, tag in tagged}
            relays_only = [r for r, _ in tagged]
            n_rounds = max(1, args.rounds or cfg.defaults.rounds)
            per_round_for_provider: list[list[tuple[Relay, ProbeResult]]] = []
            for round_i in range(n_rounds):
                if round_i > 0:
                    await asyncio.sleep(0.5)
                round_pairs = await probe_all(
                    relays_only, concurrency=80, count=cfg.defaults.count,
                    timeout_s=cfg.defaults.timeout, enable_tcp_fallback=True,
                    show_progress=False,
                )
                per_round_for_provider.append(round_pairs)
            if n_rounds > 1:
                pairs = merge_rounds(per_round_for_provider)
                ok = sum(1 for _, p in pairs if p.success)
                flap = sum(1 for r, _ in pairs if flappy(per_round_for_provider, r.id))
                print(
                    f"             → probed {len(pairs)} × {n_rounds} rounds, "
                    f"reachable {ok}" + (f", flappy {flap}" if flap else "")
                )
            else:
                pairs = per_round_for_provider[0]
                ok = sum(1 for _, p in pairs if p.success)
                print(f"             → probed {len(pairs)}, reachable {ok}")
            for r, p in pairs:
                tag = tag_by_id.get(r.id, "")
                if n_rounds > 1 and flappy(per_round_for_provider, r.id):
                    tag = f"{tag} flappy" if tag else "flappy"
                all_pairs.append((r, p, tag))
        except Exception as e:
            print(f"\n  {name}: error: {e}", file=sys.stderr)

    if not all_pairs:
        print("\nNo candidates probed. Try `nearest-exit doctor`.", file=sys.stderr)
        return 1

    # Apply per-provider weights and sticky bonus to compute effective RTT.
    weighted: list[tuple[Relay, ProbeResult, str, float]] = []
    for r, p, src in all_pairs:
        if not p.success:
            continue
        w = cfg.providers.weights.get(r.provider, 0.5)
        eff = (p.rtt_ms or math.inf) / max(w, 0.01)
        eff -= sticky_bonus(r.provider, r.id, winners)
        weighted.append((r, p, src, eff))

    if not weighted:
        print("\nNo relays reachable from this network.", file=sys.stderr)
        return 1

    weighted.sort(key=lambda t: (t[3], t[0].hostname))

    best_r, best_p, best_src, _ = weighted[0]
    print(f"\nBest:")
    print(_fmt_relay_line(best_r, best_p, best_src))

    # Alternatives: prefer provider diversity, then lowest RTT.
    seen_providers = {best_r.provider}
    diverse: list[tuple[Relay, ProbeResult, str]] = []
    same_provider: list[tuple[Relay, ProbeResult, str]] = []
    for r, p, src, _eff in weighted[1:]:
        if r.provider not in seen_providers:
            diverse.append((r, p, src))
            seen_providers.add(r.provider)
        else:
            same_provider.append((r, p, src))
    alts_n = max(2, args.top - 1)
    alts = (diverse + same_provider)[:alts_n]
    if alts:
        print("Alternatives:")
        for r, p, src in alts:
            print(_fmt_relay_line(r, p, src))

    # Nearby: best per *other* country (excludes the detected one).
    by_country: dict[str, tuple[Relay, ProbeResult]] = {}
    for r, p, _src, _eff in weighted:
        cc = (r.country_code or "").upper()
        if not cc or cc == (country_filter or "").upper():
            continue
        prev = by_country.get(cc)
        if prev is None or (p.rtt_ms or math.inf) < (prev[1].rtt_ms or math.inf):
            by_country[cc] = (r, p)
    if by_country:
        baseline = best_p.rtt_ms or 0.0
        nearby = sorted(by_country.items(),
                        key=lambda kv: kv[1][1].rtt_ms or math.inf)[:5]
        bits = []
        for cc, (r, p) in nearby:
            delta = (p.rtt_ms or 0) - baseline
            sign = "+" if delta >= 0 else "-"
            bits.append(f"{cc} {sign}{abs(delta):.0f}ms ({r.provider})")
        print(f"Nearby: {'   '.join(bits)}")

    # Footer: how to reproduce.
    print(f"\nProbed {len(all_pairs)} relays across {len(pref_order)} providers. "
          f"Use `nearest-exit scan --provider <name>` for full per-provider rankings.")

    # Record top results to history.
    rows = []
    for i, (r, p, _src, _eff) in enumerate(weighted[: max(10, args.top)], 1):
        rows.append({
            "provider": r.provider,
            "relay_id": r.id,
            "hostname": r.hostname,
            "country_code": r.country_code,
            "rtt_ms": p.rtt_ms,
            "loss": p.loss,
            "jitter_ms": p.jitter_ms,
            "success": p.success,
            "rank": i,
        })
    try:
        record_scan(rows, fp)
    except Exception as e:
        print(f"warning: could not record history: {e}", file=sys.stderr)

    return 0


async def cmd_history(args: argparse.Namespace) -> int:
    cfg = load_config()
    geo = await asyncio.to_thread(
        resolve_geo, cfg.geo.lookup, cfg.geo.country, cfg.geo.coords, cfg.geo.mmdb_path,
    )
    fp = network_fingerprint(geo.asn, geo.ip)
    winners = recent_winners(fp, since_seconds=args.window * 86400)
    if not winners:
        print(f"no recorded winners on this network in the last {args.window} day(s).")
        return 0
    print(f"network fingerprint: {fp}  (last {args.window} day(s))")
    print(f"{'count':>6}  provider   relay")
    for (provider, rid), n in sorted(winners.items(), key=lambda kv: -kv[1]):
        print(f"{n:>6}  {provider:<10} {rid}")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    print(f"platform:        {sys.platform}")
    print(f"python:          {sys.version.split()[0]}")
    print(f"ping available:  {ping_available()}")
    print(f"vpn route:       {detect_vpn() or 'no'}")
    print(f"cache dir:       {default_cache_dir()}")
    print(f"config path:     {default_config_path()}")
    print(f"config exists:   {default_config_path().exists()}")
    return 0


def cmd_prefs_init(args: argparse.Namespace) -> int:
    p = write_default_config()
    print(f"wrote default config to {p}")
    return 0


def cmd_prefs_show(args: argparse.Namespace) -> int:
    cfg = load_config()
    print(f"config:    {default_config_path()}  (exists={default_config_path().exists()})")
    print(f"order:     {cfg.providers.order}")
    print(f"weights:   {cfg.providers.weights}")
    print(f"others:    allowed={cfg.providers.others_allowed} "
          f"threshold_ms={cfg.providers.others_threshold_ms}")
    print(f"defaults:  scope={cfg.defaults.scope} feature={cfg.defaults.feature} "
          f"top={cfg.defaults.top} count={cfg.defaults.count}")
    print(f"geo:       lookup={cfg.geo.lookup}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="nearest-exit")
    p.add_argument("--here", metavar="CC",
                   help="Override detected country (ISO 3166-1 alpha-2, e.g. YE).")
    p.add_argument("--coords", nargs=2, type=float, metavar=("LAT", "LON"),
                   help="Override detected coordinates.")
    p.add_argument("--lookup", choices=("ipinfo", "stun", "none"),
                   help="Override geo lookup mode for this run.")
    p.add_argument("--rounds", type=int, default=0,
                   help="Probe each relay N rounds; useful on flappy links "
                        "(Starlink POP shifts, mobile). Defaults to config.")
    p.set_defaults(func=cmd_default, _async=True, country=None, top=4)
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="Probe and rank relays.")
    s.add_argument("--provider", choices=PROVIDER_NAMES, default="mullvad")
    s.add_argument("--country", help="Country code or name.")
    s.add_argument("--city")
    s.add_argument("--protocol", help="e.g. wireguard, openvpn")
    s.add_argument("--technology", help="NordVPN technology id (e.g. wireguard_udp)")
    s.add_argument("--include-inactive", action="store_true")
    s.add_argument("--owned", action=argparse.BooleanOptionalAction, default=None)
    s.add_argument("--top", type=int, default=10)
    s.add_argument("--count", type=int, default=4)
    s.add_argument("--timeout", type=float, default=2.0)
    s.add_argument("--concurrency", type=int, default=100)
    s.add_argument("--refresh", action="store_true")
    s.add_argument("--no-tcp-fallback", action="store_true",
                   help="Disable TCP/443 fallback when ICMP fails.")
    s.add_argument("--geofilter", type=int, default=0,
                   help="Probe only the K relays nearest to the detected location.")
    s.add_argument("--json", action="store_true")
    s.add_argument("-v", "--verbose", action="store_true")
    s.set_defaults(func=cmd_scan, _async=True)

    d = sub.add_parser("doctor", help="Show local diagnostics.")
    d.set_defaults(func=cmd_doctor, _async=False)

    h = sub.add_parser("history", help="Show recent winners on this network.")
    h.add_argument("--window", type=int, default=7, help="Days to look back.")
    h.set_defaults(func=cmd_history, _async=True)

    pr = sub.add_parser("prefs", help="View or initialize preferences.")
    pr_sub = pr.add_subparsers(dest="prefs_cmd")
    pr_init = pr_sub.add_parser("init", help="Write default config.toml.")
    pr_init.set_defaults(func=cmd_prefs_init, _async=False)
    pr_show = pr_sub.add_parser("show", help="Print current config.")
    pr_show.set_defaults(func=cmd_prefs_show, _async=False)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    if getattr(args, "_async", False):
        return asyncio.run(args.func(args))
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
