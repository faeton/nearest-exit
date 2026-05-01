from __future__ import annotations

import argparse
import asyncio
import json
import math
import sys
from dataclasses import asdict

from .cache import JsonCache, default_cache_dir
from .config import Config, default_config_path, load_config, write_default_config
from .diagnostics import detect_vpn, ping_available
from .doh import resolve_a
from .geo import GeoContext, lookup_ipinfo
from .geofilter import top_k_by_distance
from .history import (
    network_fingerprint,
    record_scan,
    recent_winners,
    sticky_bonus,
)
from .models import ProbeResult, Relay
from .probes.icmp import icmp_probe
from .probes.tcp import tcp_probe
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
):
    sem = asyncio.Semaphore(concurrency)
    total = len(relays)
    done = 0
    progress = sys.stderr.isatty()

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


async def cmd_default(args: argparse.Namespace) -> int:
    """Headline action: detect context → preferred providers → best + nearby."""
    cfg = load_config()
    cache = JsonCache(ttl_seconds=24 * 3600)

    if vpn := detect_vpn():
        print(
            f"warning: default route via {vpn} (VPN tunnel). "
            f"Disconnect for accurate results.",
            file=sys.stderr,
        )

    geo: GeoContext = GeoContext()
    if cfg.geo.lookup == "ipinfo":
        geo = await asyncio.to_thread(lookup_ipinfo)

    here = []
    if geo.city or geo.country_code:
        here.append(f"{geo.city or '?'}, {(geo.country_code or '?').upper()}")
    if geo.org:
        here.append(geo.org)
    if vpn:
        here.append(f"via {vpn}")
    if here:
        print(f"You: {' — '.join(here)}", file=sys.stderr)

    country_filter = args.country or geo.country_code

    pref_order = [p for p in cfg.providers.order if p in PROVIDER_NAMES]
    if not pref_order:
        pref_order = list(PROVIDER_NAMES)

    fp = network_fingerprint(geo.asn)
    winners = recent_winners(fp)

    all_pairs: list[tuple[Relay, ProbeResult]] = []
    for name in pref_order:
        try:
            provider = await build_provider(
                name, country=country_filter, technology=None, cache=cache,
            )
            relays = await provider.fetch_relays(cache, refresh=False)
            relays = filter_relays(
                relays,
                country=country_filter,
                city=None,
                protocol=cfg.defaults.feature,
                active_only=True,
                owned=None,
            )
            if not relays:
                print(f"  {name}: no relays in {country_filter}", file=sys.stderr)
                continue
            # Geofilter to top-K nearest by haversine before probing.
            relays = top_k_by_distance(relays, geo.latitude, geo.longitude, k=60)
            pairs = await probe_all(
                relays, concurrency=80, count=cfg.defaults.count,
                timeout_s=cfg.defaults.timeout, enable_tcp_fallback=True,
            )
            all_pairs.extend(pairs)
        except Exception as e:
            print(f"  {name}: error: {e}", file=sys.stderr)

    if not all_pairs:
        print("No candidates probed. Try `nearest-exit doctor`.", file=sys.stderr)
        return 1

    weighted: list[tuple[Relay, ProbeResult, float]] = []
    for r, p in all_pairs:
        if not p.success:
            continue
        w = cfg.providers.weights.get(r.provider, 0.5)
        # Weighted RTT: divide by weight so a lower-weighted provider needs
        # to be proportionally faster. Effective RTT used only for ranking;
        # the displayed RTT remains the measured one.
        eff = (p.rtt_ms or math.inf) / max(w, 0.01)
        eff -= sticky_bonus(r.provider, r.id, winners)
        weighted.append((r, p, eff))

    if not weighted:
        print("No relays reachable from this network.", file=sys.stderr)
        return 1

    weighted.sort(key=lambda t: (t[2], t[0].hostname))

    best_r, best_p, _ = weighted[0]
    print()
    print(f"Best: {best_r.provider:<8} {best_r.hostname:<24} "
          f"{(best_r.protocols[0] if best_r.protocols else ''):<10} "
          f"{best_p.rtt_ms:.1f}ms  loss {(best_p.loss or 0)*100:.0f}%"
          + (f"  load {best_r.load:.0f}%" if best_r.load is not None else ""))

    alts = weighted[1:1 + max(0, args.top - 1)]
    if alts:
        print("Also:")
        for r, p, _eff in alts:
            print(f"  {r.provider:<8} {r.hostname:<24} "
                  f"{(r.protocols[0] if r.protocols else ''):<10} "
                  f"{p.rtt_ms:.1f}ms  loss {(p.loss or 0)*100:.0f}%"
                  + (f"  load {r.load:.0f}%" if r.load is not None else ""))

    # Nearby: top reachable per other country
    by_country: dict[str, tuple[Relay, ProbeResult]] = {}
    for r, p, _ in weighted:
        cc = (r.country_code or "").upper()
        if not cc or cc == (country_filter or "").upper():
            continue
        if cc not in by_country:
            by_country[cc] = (r, p)
    if by_country:
        nearby = sorted(by_country.items(), key=lambda kv: kv[1][1].rtt_ms or math.inf)[:5]
        baseline = best_p.rtt_ms or 0.0
        bits = [f"{cc} +{(p.rtt_ms - baseline):.0f}ms" for cc, (_, p) in nearby]
        print(f"Nearby: {'  '.join(bits)}")

    # Record top results to history (rank 1 = best).
    rows = []
    for i, (r, p, _eff) in enumerate(weighted[: max(10, args.top)], 1):
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
    geo = await asyncio.to_thread(lookup_ipinfo)
    fp = network_fingerprint(geo.asn)
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
    p.set_defaults(func=cmd_default, _async=True, country=None, top=3)
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
