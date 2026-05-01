from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import asdict

from .cache import JsonCache, default_cache_dir
from .diagnostics import detect_vpn, ping_available
from .models import Relay
from .probes.icmp import icmp_probe
from .providers.mullvad import MullvadProvider
from .scoring import rank

PROVIDERS = {"mullvad": MullvadProvider}


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


async def probe_all(relays: list[Relay], concurrency: int, count: int, timeout_s: float):
    sem = asyncio.Semaphore(concurrency)
    total = len(relays)
    done = 0
    progress = sys.stderr.isatty()

    async def run(r: Relay):
        nonlocal done
        async with sem:
            res = await icmp_probe(r.id, r.ipv4 or "", count=count, timeout_s=timeout_s)
        done += 1
        if progress:
            print(f"\rprobed {done}/{total}", end="", file=sys.stderr, flush=True)
        return r, res

    pairs = await asyncio.gather(*(run(r) for r in relays))
    if progress:
        print("", file=sys.stderr)
    return list(pairs)


def print_table(ranked, top: int) -> None:
    cols = ("rank", "provider", "server", "country", "city", "protocol", "ipv4", "rtt", "loss", "jitter")
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
            f"{p.rtt_ms:.1f}ms" if p.rtt_ms is not None else "—",
            f"{p.loss * 100:.0f}%" if p.loss is not None else "—",
            f"{p.jitter_ms:.1f}ms" if p.jitter_ms is not None else "—",
        ))
    widths = [max(len(c), max((len(r[i]) for r in rows), default=0)) for i, c in enumerate(cols)]
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
    provider = PROVIDERS[args.provider]()

    if vpn := detect_vpn():
        print(
            f"WARNING: default route via {vpn} (looks like a VPN tunnel). "
            f"Latencies will be tunnel-routed; disconnect for accurate results.",
            file=sys.stderr,
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

    if args.verbose:
        print(f"probing {len(relays)} relays via ICMP...", file=sys.stderr)

    pairs = await probe_all(
        relays,
        concurrency=args.concurrency,
        count=args.count,
        timeout_s=args.timeout,
    )
    ranked = rank(pairs)

    if not any(rr.probe.success for rr in ranked):
        print(
            "WARNING: no relays replied to ICMP. Network may block ping; "
            "TCP fallback probe is planned for V2.",
            file=sys.stderr,
        )

    if args.json:
        print_json(ranked, args.top)
    else:
        print_table(ranked, args.top)
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    print(f"platform:        {sys.platform}")
    print(f"python:          {sys.version.split()[0]}")
    print(f"ping available:  {ping_available()}")
    print(f"vpn route:       {detect_vpn() or 'no'}")
    print(f"cache dir:       {default_cache_dir()}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="nearest-exit")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="Probe and rank relays.")
    s.add_argument("--provider", choices=PROVIDERS.keys(), default="mullvad")
    s.add_argument("--country", help="Country code or name.")
    s.add_argument("--city")
    s.add_argument("--protocol", help="e.g. wireguard, openvpn")
    s.add_argument("--include-inactive", action="store_true")
    s.add_argument("--owned", action=argparse.BooleanOptionalAction, default=None)
    s.add_argument("--top", type=int, default=10)
    s.add_argument("--count", type=int, default=4)
    s.add_argument("--timeout", type=float, default=2.0)
    s.add_argument("--concurrency", type=int, default=100)
    s.add_argument("--refresh", action="store_true", help="Bypass metadata cache.")
    s.add_argument("--json", action="store_true")
    s.add_argument("-v", "--verbose", action="store_true")
    s.set_defaults(func=cmd_scan, _async=True)

    d = sub.add_parser("doctor", help="Show local diagnostics.")
    d.set_defaults(func=cmd_doctor, _async=False)

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
