from __future__ import annotations

import argparse
import asyncio
import json
import math
import re
import sys
from dataclasses import asdict
from pathlib import Path

from .cache import JsonCache, default_cache_dir
from .config import (
    KNOWN_PROVIDERS,
    default_config_path,
    load_config,
    validate_config,
    write_default_config,
)
from .countries import merged_centroids, nearest_countries
from .diagnostics import detect_vpn, ping_available
from .doh import resolve_a
from .geo import GeoContext, resolve_geo
from .geofilter import top_k_by_distance
from .history import (
    STICKY_RTT_BONUS_CAP_MS,
    network_fingerprint,
    recent_winners,
    record_scan,
)
from .models import ProbeResult, Relay
from .probes import probe_family
from .probes.icmp import icmp_probe
from .probes.ike import ike_probe
from .probes.openvpn import openvpn_probe
from .probes.socks5 import socks5_probe
from .probes.tcp import tcp_probe
from .providers.airvpn import AirVPNProvider
from .providers.mullvad import MullvadProvider
from .providers.nordvpn import (
    FLEET_SIZE_FIELD as NORDVPN_FLEET_SIZE_FIELD,
)
from .providers.nordvpn import (
    NordVPNProvider,
    country_code_to_id,
    fetch_countries,
)
from .providers.pia import PIAProvider
from .render import FORMATS, JSON, TABLE, render
from .rounds import flappy, merge_rounds
from .scoring import apply_preference_threshold, probe_cost_ms, rank
from .targets import (
    ikev2_targets,
    is_probeable_address,
    openvpn_targets,
    relay_entry_ips,
    tcp_fallback_targets,
)

PROVIDER_NAMES = KNOWN_PROVIDERS
SCAN_PROVIDER_CHOICES = (*PROVIDER_NAMES, "all")

# Protocols that actually carry exit traffic. A Mullvad "bridge" relay is
# entry obfuscation and a socks-only server is a proxy; neither can be the
# exit this tool recommends, so ranking them is a category error rather than
# a quality judgement.
EXIT_PROTOCOLS = frozenset({"wireguard", "openvpn", "ikev2"})

# How to measure, which is a separate question from which relays qualify
# (`--protocol`). `auto` tries ICMP, then IKEv2 where the provider publishes
# it, then a TCP connect; the rest pin one method so the whole table is
# measured the same way and stays comparable.
PROBE_AUTO = "auto"
PROBE_ICMP = "icmp"
PROBE_TCP = "tcp"
PROBE_OPENVPN = "openvpn"
PROBE_IKEV2 = "ikev2"
PROBE_SOCKS5 = "socks5"
PROBE_CHOICES = (
    PROBE_AUTO, PROBE_ICMP, PROBE_TCP, PROBE_OPENVPN, PROBE_IKEV2, PROBE_SOCKS5,
)

SCOPE_HERE = "here"
SCOPE_NEARBY = "nearby"
SCOPE_GLOBAL = "global"
SCOPE_CHOICES = (SCOPE_HERE, SCOPE_NEARBY, SCOPE_GLOBAL)

# How many reachable relays get written to history per run, independent of how
# many are displayed.
HISTORY_RECORD_TOP = 10

# Version of the `--json` object emitted by the default flow. Version 1
# replaced `effective_rtt_ms` with the `measured_cost_ms` / `effective_cost_ms`
# pair. `scan --json` emits a bare array of ranked items and carries no
# version of its own.
JSON_SCHEMA_VERSION = 1


def _positive_int(value: str) -> int:
    try:
        out = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected a whole number, got {value!r}") from None
    if out < 1:
        raise argparse.ArgumentTypeError(f"must be 1 or more, got {out}")
    return out


def _non_negative_int(value: str) -> int:
    try:
        out = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected a whole number, got {value!r}") from None
    if out < 0:
        raise argparse.ArgumentTypeError(f"must be 0 or more, got {out}")
    return out


def _positive_float(value: str) -> float:
    try:
        out = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected a number, got {value!r}") from None
    if not (out > 0 and math.isfinite(out)):
        raise argparse.ArgumentTypeError(f"must be greater than 0, got {value!r}")
    return out


def _warn_config(cfg) -> None:
    for warning in validate_config(cfg, PROVIDER_NAMES):
        print(f"WARNING: config: {warning}", file=sys.stderr)


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
    if name == "pia":
        return PIAProvider()
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
        available = {p.lower() for p in r.protocols}
        if protocol:
            if protocol.lower() not in available:
                continue
        elif not available & EXIT_PROTOCOLS:
            # Nothing specific was asked for, so only real exits qualify.
            continue
        if active_only and r.active is False:
            continue
        if owned is not None and r.owned != owned:
            continue
        if not r.ipv4 and not _resolvable_hostname(r.hostname):
            # Dropping everything without an ipv4 meant `_ensure_ipv4`'s DoH
            # fallback could never fire. Keep relays whose hostname is at
            # least a DNS name — provider ids are not always resolvable
            # (PIA region slugs, AirVPN public names).
            continue
        out.append(r)
    return out


def _resolvable_hostname(host: str | None) -> bool:
    return bool(host) and "." in host


async def _resolve_host(host: str) -> str | None:
    """Resolve to a probeable IPv4 address, or None.

    Refuses addresses that cannot be a public relay. Provider metadata is not
    always about the public internet — Mullvad's SOCKS5 names resolve into
    10.124.0.0/16 — and probing those would scan the user's own network.
    """
    if not host:
        return None
    if _looks_like_ipv4(host):
        return host if is_probeable_address(host) else None
    ips = await asyncio.to_thread(resolve_a, host)
    for ip in ips:
        if is_probeable_address(ip):
            return ip
    return None


def _looks_like_ipv4(host: str) -> bool:
    parts = host.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


async def _ensure_ipv4(relay: Relay) -> str | None:
    """Return relay.ipv4, or resolve hostname via DoH if missing."""
    if relay.ipv4:
        return relay.ipv4
    if not relay.hostname:
        return None
    return await _resolve_host(relay.hostname)


def _best_probe(results: list[ProbeResult]) -> ProbeResult:
    """Pick the best of several probe targets belonging to one relay.

    Ranked by the same cost function used to rank relays. Ordering on raw RTT
    picked a 10ms target losing half its packets over a clean 20ms one.
    """
    if not results:
        raise ValueError("no probe results")
    return min(
        results,
        key=lambda p: (0 if p.success else 1, probe_cost_ms(p), p.target),
    )


async def _run_limited(limiter: asyncio.Semaphore | None, coro):
    if limiter is None:
        return await coro
    async with limiter:
        return await coro


async def _probe_targets(
    relay: Relay,
    targets,
    probe_fn,
    count: int,
    timeout_s: float,
    default_port: int | None,
    limiter: asyncio.Semaphore | None,
) -> list[ProbeResult]:
    """Resolve and probe every target for one relay concurrently."""

    async def one(target) -> ProbeResult | None:
        ip = await _resolve_host(target.host)
        port = target.port or default_port
        if not ip or port is None:
            return None
        return await _run_limited(
            limiter,
            probe_fn(relay.id, ip, port=port, count=count, timeout_s=timeout_s),
        )

    results = await asyncio.gather(*(one(t) for t in targets))
    return [r for r in results if r is not None]


def _unprobeable(relay: Relay, kind: str, why: str) -> ProbeResult:
    return ProbeResult(
        relay_id=relay.id, probe=kind, target=relay.hostname,
        success=False, rtt_ms=None, loss=1.0, jitter_ms=None,
        samples=(), error=why,
    )


async def _probe_openvpn(relay, count, timeout_s, limiter) -> ProbeResult:
    """Measure the OpenVPN daemon rather than the IP stack in front of it.

    PIA answers an unauthenticated control-channel reset outright; AirVPN and
    NordVPN run tls-auth, so they read it, fail the HMAC and close — which is
    still a round trip through the daemon. Mullvad has no OpenVPN fleet, so it
    has no target here at all.
    """
    targets = openvpn_targets(relay)
    if not targets:
        return _unprobeable(
            relay, "openvpn", f"{relay.provider} publishes no OpenVPN endpoint"
        )

    async def one(target):
        ip = await _resolve_host(target.host)
        if not ip or target.port is None:
            return None
        transport = "udp" if target.kind == "openvpn-udp" else "tcp"
        return await _run_limited(
            limiter,
            openvpn_probe(
                relay.id, ip, port=target.port, count=count,
                timeout_s=timeout_s, transport=transport,
            ),
        )

    results = [r for r in await asyncio.gather(*(one(t) for t in targets)) if r]
    if results:
        return _best_probe(results)
    return _unprobeable(relay, "openvpn", "no OpenVPN target resolved")


async def _probe_ikev2(relay, count, timeout_s, limiter) -> ProbeResult:
    """Measure the IKEv2 daemon by having it refuse an unauthenticated proposal.

    Only NordVPN: see `targets.ikev2_targets` for why PIA is excluded despite
    publishing an endpoint.
    """
    targets = ikev2_targets(relay)
    if not targets:
        return _unprobeable(
            relay, "ikev2", f"{relay.provider} publishes no IKEv2 endpoint"
        )

    async def one(target):
        ip = await _resolve_host(target.host)
        if not ip or target.port is None:
            return None
        return await _run_limited(
            limiter,
            ike_probe(
                relay.id, ip, port=target.port, count=count, timeout_s=timeout_s
            ),
        )

    results = [r for r in await asyncio.gather(*(one(t) for t in targets)) if r]
    if results:
        return _best_probe(results)
    return _unprobeable(relay, "ikev2", "no IKEv2 target resolved")


async def probe_one(relay: Relay, count: int, timeout_s: float,
                    enable_tcp_fallback: bool,
                    feature: str | None = None,
                    limiter: asyncio.Semaphore | None = None,
                    probe_kind: str = PROBE_AUTO) -> ProbeResult:
    if probe_kind == PROBE_OPENVPN:
        return await _probe_openvpn(relay, count, timeout_s, limiter)

    if probe_kind == PROBE_IKEV2:
        return await _probe_ikev2(relay, count, timeout_s, limiter)

    if probe_kind == PROBE_SOCKS5 or (probe_kind == PROBE_AUTO and feature == "socks5"):
        results = await _probe_targets(
            relay, tcp_fallback_targets(relay, "socks5"), socks5_probe,
            count, timeout_s, default_port=1080, limiter=limiter,
        )
        if results:
            return _best_probe(results)
        return _unprobeable(relay, "socks5", "no SOCKS5 target")

    if probe_kind == PROBE_TCP:
        results = await _probe_targets(
            relay, tcp_fallback_targets(relay, feature), tcp_probe,
            count, timeout_s, default_port=443, limiter=limiter,
        )
        if results:
            return _best_probe(results)
        return _unprobeable(relay, "tcp", "no TCP target")

    ips = relay_entry_ips(relay)
    if not ips:
        ip = await _ensure_ipv4(relay)
        ips = [ip] if ip else []
    if not ips:
        return ProbeResult(
            relay_id=relay.id, probe="none", target=relay.hostname,
            success=False, rtt_ms=None, loss=1.0, jitter_ms=None,
            samples=(), error="no IP (DoH failed)",
        )

    # AirVPN publishes up to four entry IPs per server. Probing them one after
    # another cost four serial ping runs per relay for no reason.
    icmp_results = list(await asyncio.gather(*(
        _run_limited(limiter, icmp_probe(relay.id, ip, count=count, timeout_s=timeout_s))
        for ip in ips
    )))
    icmp = _best_probe(icmp_results)
    if icmp.success or not enable_tcp_fallback or probe_kind == PROBE_ICMP:
        return icmp

    # Where the provider publishes IKEv2, try it before falling back to a TCP
    # connect. Both are fallbacks, but they are not equal evidence: a TCP
    # connect completes in the kernel of whatever happens to answer port 443 —
    # a load balancer, a TLS terminator — while an IKE_SA_INIT refusal has to
    # come from the VPN daemon, which is the thing being ranked. It also
    # matters more than it sounds: from a vantage point where ICMP is filtered,
    # this is most of the fleet rather than a rare edge. Only NordVPN publishes
    # an IKEv2 endpoint, so this is a no-op for every other provider.
    if ikev2_targets(relay):
        ike = await _probe_ikev2(relay, max(2, count - 1), timeout_s, limiter)
        if ike.success:
            return ike

    tcp_results = await _probe_targets(
        relay, tcp_fallback_targets(relay, feature), tcp_probe,
        max(2, count - 1), timeout_s, default_port=None, limiter=limiter,
    )
    return _best_probe(tcp_results) if tcp_results else icmp


async def probe_all(
    relays: list[Relay],
    concurrency: int,
    count: int,
    timeout_s: float,
    enable_tcp_fallback: bool = True,
    show_progress: bool = True,
    feature: str | None = None,
    probe_kind: str = PROBE_AUTO,
):
    # A semaphore of 0 never releases, so a zero/negative concurrency would
    # hang forever rather than failing. Clamp instead of deadlocking.
    limit = max(1, concurrency)
    sem = asyncio.Semaphore(limit)
    # Relay-level concurrency understates how many probes are actually in
    # flight, because one relay can fan out to several entry IPs. This bounds
    # the real number of `ping` processes and sockets, which matters because
    # self-induced congestion looks exactly like a lossy relay. Created per
    # call so it is never shared across event loops.
    # Not a multiple of `limit`: pinging four entry IPs of eighty relays at
    # once induces the very loss the score then charges for.
    target_sem = asyncio.Semaphore(limit)
    total = len(relays)
    done = 0
    progress = show_progress and sys.stderr.isatty()

    async def run(r: Relay):
        nonlocal done
        async with sem:
            res = await probe_one(
                r, count, timeout_s, enable_tcp_fallback, feature, target_sem,
                probe_kind,
            )
        done += 1
        if progress:
            print(f"\rprobed {done}/{total}", end="", file=sys.stderr, flush=True)
        return r, res

    pairs = await asyncio.gather(*(run(r) for r in relays))
    if progress:
        print("", file=sys.stderr)
    return list(pairs)


def _fmt_ms(value: float | None) -> str:
    return f"{value:.1f}ms" if value is not None else "—"


def _mixed_probe_note(rows) -> str | None:
    """Say so when a ranking compares numbers produced by different probes.

    `auto` falls through ICMP → IKEv2 → TCP per relay, so one table can hold
    three kinds of number measuring three different amounts of work: ICMP is
    answered by the kernel, an IKEv2 refusal costs the daemon an SA-payload
    parse, a TCP connect includes a handshake. Every row already names its
    probe — but naming is not warning, and a ranked table exists precisely to
    invite comparison *across* rows.

    Deliberately a disclosure and not a correction. Calibrating one probe
    against another would mean inventing a per-probe constant this project has
    no way to measure, which is exactly the kind of confident-looking number
    the rest of the tool refuses to print.
    """
    families = sorted({
        probe_family(rr.probe.probe) for rr in rows if rr.probe.success
    })
    if len(families) < 2:
        return None
    return (
        f"Note: mixed probes ({', '.join(families)}). They measure different "
        f"amounts of work, so a gap between two rows measured differently is "
        f"weaker evidence than the same gap within one probe."
    )


def print_table(ranked, top: int, why: bool = False, fmt: str = TABLE) -> None:
    cols = ["rank", "provider", "server", "country", "city", "protocol",
            "ipv4", "probe", "rtt", "loss", "jitter", "cost", "ranked"]
    # In a terminal the derivation reads better interleaved under each row.
    # A CSV or Markdown table has nowhere to put a free-floating line, so the
    # same information becomes a column rather than being dropped.
    inline_reasons = why and fmt == TABLE
    if why and not inline_reasons:
        cols.append("reasons")

    rows = []
    for i, rr in enumerate(ranked[:top], 1):
        r, p = rr.relay, rr.probe
        row = [
            str(i),
            r.provider,
            r.hostname,
            r.country_code or "",
            r.city or "",
            (r.protocols[0] if r.protocols else ""),
            r.ipv4 or "",
            p.probe,
            _fmt_ms(p.rtt_ms),
            f"{p.loss * 100:.0f}%" if p.loss is not None else "—",
            _fmt_ms(p.jitter_ms),
            _fmt_ms(rr.measured_cost_ms),
            _fmt_ms(rr.effective_cost_ms),
        ]
        if why and not inline_reasons:
            row.append("; ".join(rr.reasons))
        rows.append(row)

    body = render(cols, rows, fmt)
    if inline_reasons:
        lines = body.splitlines()
        print(lines[0])
        for line, rr in zip(lines[1:], ranked[:top], strict=False):
            print(line)
            for reason in rr.reasons:
                print(f"      · {reason}")
    else:
        print(body)

    if note := _mixed_probe_note(ranked[:top]):
        # A caveat printed into a CSV would be parsed as a row. Machine
        # formats keep stdout to the data and put the prose where prose goes.
        print(note, file=sys.stdout if fmt == TABLE else sys.stderr)


def _ranked_json_item(rr, rank: int, source: str = "") -> dict:
    return {
        "rank": rank,
        "source": source,
        # What we measured, and what we ranked by. They differ whenever a
        # provider preference or history bonus applies, so both are reported.
        "measured_cost_ms": rr.measured_cost_ms,
        "effective_cost_ms": rr.effective_cost_ms,
        "relay": {k: v for k, v in asdict(rr.relay).items() if k != "metadata"},
        "probe": asdict(rr.probe),
        "reasons": list(rr.reasons),
    }


def print_json(ranked, top: int) -> None:
    print(json.dumps(
        [_ranked_json_item(rr, i) for i, rr in enumerate(ranked[:top], 1)],
        indent=2, default=str,
    ))


def _cache_from_args(args: argparse.Namespace, ttl_seconds: int = 24 * 3600) -> JsonCache:
    """Build the run's cache from `--cache-dir` / `--no-cache`."""
    cache_dir = getattr(args, "cache_dir", None)
    return JsonCache(
        cache_dir=Path(cache_dir).expanduser() if cache_dir else None,
        ttl_seconds=ttl_seconds,
        enabled=not getattr(args, "no_cache", False),
    )


def _warn_if_tunnelled(args: argparse.Namespace) -> str | None:
    """Say what a VPN default route does to the numbers, once, unless silenced.

    The tool measures anyway rather than refusing, because a tunnel is a
    legitimate place to ask "what should I switch to?". But every RTT is then
    the path *through the current tunnel* to the candidate, which is a
    different quantity from the one the table claims to rank, and it is
    systematically worse for relays near the current exit.
    """
    vpn = detect_vpn()
    if vpn and not getattr(args, "ignore_vpn_route_warning", False):
        print(
            f"warning: default route via {vpn} (VPN tunnel). Every measurement "
            f"below is the path through that tunnel, not from you to the relay, "
            f"so the ranking is about the tunnel as much as the relays. "
            f"Disconnect for a clean run, or pass --ignore-vpn-route-warning "
            f"to silence this.",
            file=sys.stderr,
        )
    return vpn


async def cmd_scan(args: argparse.Namespace) -> int:
    # `scan` used to ignore the config completely: no provider preferences, no
    # validation warnings. The scoring function was shared with the default
    # flow but the inputs were not, so the two commands disagreed.
    cfg = load_config()
    _warn_config(cfg)
    probe_kind = args.probe or cfg.defaults.probe
    cache = _cache_from_args(args)

    _warn_if_tunnelled(args)

    provider_names = list(PROVIDER_NAMES) if args.provider == "all" else [args.provider]
    relays: list[Relay] = []
    provider_errors: list[tuple[str, str]] = []
    for provider_name in provider_names:
        try:
            provider = await build_provider(
                provider_name,
                country=args.country,
                technology=args.technology if provider_name == "nordvpn" else None,
                cache=cache,
            )
            relays.extend(await provider.fetch_relays(cache, refresh=args.refresh))
        except Exception as e:
            provider_errors.append((provider_name, str(e)))
            print(f"WARNING: {provider_name}: fetch failed: {e}", file=sys.stderr)

    relays = filter_relays(
        relays,
        country=args.country,
        city=args.city,
        protocol=args.protocol,
        active_only=not args.include_inactive,
        owned=args.owned,
    )
    if not relays:
        if provider_errors:
            failed = ", ".join(name for name, _ in provider_errors)
            print(f"No relays match filters; provider fetch failed for: {failed}.", file=sys.stderr)
        else:
            print("No relays match filters.", file=sys.stderr)
        return 1

    if args.geofilter and args.geofilter > 0 and len(relays) > args.geofilter:
        # Was hardcoded to lookup_ipinfo(), so `--lookup none` still made a
        # network call and manual coordinates were ignored on this path.
        geo = await asyncio.to_thread(
            resolve_geo,
            args.lookup or cfg.geo.lookup,
            args.country or cfg.geo.country,
            tuple(args.coords) if args.coords else cfg.geo.coords,
            cfg.geo.mmdb_path,
        )
        if geo.latitude is None or geo.longitude is None:
            print(
                "WARNING: --geofilter needs a location and none could be "
                f"determined (geo: {geo.source}); probing all relays instead. "
                "Pass --coords LAT LON or --country CC.",
                file=sys.stderr,
            )
        else:
            relays = top_k_by_distance(
                relays, geo.latitude, geo.longitude, k=args.geofilter
            )
            if args.verbose:
                print(
                    f"geofiltered to {len(relays)} nearest "
                    f"(from {geo.city or '?'}, {(geo.country_code or '?').upper()})",
                    file=sys.stderr,
                )

    if args.verbose:
        print(f"probing {len(relays)} relays...", file=sys.stderr)

    pairs = await probe_all(
        relays,
        concurrency=args.concurrency,
        count=args.count or cfg.defaults.count,
        timeout_s=args.timeout or cfg.defaults.timeout,
        enable_tcp_fallback=not args.no_tcp_fallback,
        feature=args.protocol,
        probe_kind=probe_kind,
    )
    # `scan` is the audit trail: by default it orders on measurement alone, so
    # there is always a way to see what the network actually said, independent
    # of any preference. `--preferences` opts into the default flow's policy.
    # History is never consulted or recorded here — rank 1 within a
    # single-provider scan is not a winner for the network.
    penalties = cfg.providers.penalties_ms if args.preferences else None
    if args.preferences and penalties:
        print(
            "applying provider preferences: "
            + ", ".join(f"{n} +{ms:g}ms" for n, ms in sorted(penalties.items())),
            file=sys.stderr,
        )
    ranked = rank(pairs, provider_penalties=penalties)

    if not any(rr.probe.success for rr in ranked):
        # Naming the actual failure matters now that --probe can pick a method
        # a provider does not run at all; "ICMP and TCP both failed" was a
        # guess that happened to be true only for the default ladder.
        reason = _why_unreachable([(rr.relay, rr.probe) for rr in ranked], 0)
        detail = reason.strip(" ()") or (
            "network may block all outbound probes"
            if probe_kind == PROBE_AUTO
            else f"nothing answered the {probe_kind} probe"
        )
        print(f"WARNING: no relays replied: {detail}.", file=sys.stderr)

    top = args.top or cfg.defaults.top
    # `--json` predates `--format` and still works; it is the same request.
    fmt = getattr(args, "format", None) or (JSON if args.json else TABLE)
    if fmt == JSON:
        print_json(ranked, top)
    else:
        print_table(ranked, top, why=args.why, fmt=fmt)
    return 0


def _country_label(r: Relay) -> str:
    cc = (r.country_code or "").upper()
    name = r.country_name or ""
    if name and cc:
        return f"{name} ({cc})"
    return name or cc or "??"


def _fmt_relay_line(rr, source: str = "") -> str:
    r, p = rr.relay, rr.probe
    proto = r.protocols[0] if r.protocols else ""
    rtt = f"{p.rtt_ms:.1f}ms" if p.rtt_ms is not None else "—"
    if p.jitter_ms is not None and p.jitter_ms >= 1.0:
        rtt = f"{rtt} ±{p.jitter_ms:.0f}ms"
    target = p.target or r.ipv4 or ""
    probe_label = p.probe if p.probe else "?"
    country = _country_label(r)
    where = f"{r.city}, {country}" if r.city else country
    bits = [
        f"{r.provider:<8}",
        f"{r.hostname:<26}",
        f"{where:<28}",
        f"{proto:<10}",
        f"{probe_label}→{target:<15}",
        f"{rtt:<16}",
        f"loss {(p.loss or 0) * 100:.0f}%",
    ]
    if r.load is not None:
        bits.append(f"load {r.load:.0f}%")
    # Show what we ranked by, not only what we measured. These diverge as soon
    # as a provider preference or history bonus applies, and printing only the
    # raw RTT made the ordering look arbitrary.
    if rr.measured_cost_ms is not None:
        bits.append(f"= {rr.measured_cost_ms:.1f}ms")
        if (
            rr.effective_cost_ms is not None
            and abs(rr.effective_cost_ms - rr.measured_cost_ms) >= 0.05
        ):
            delta = rr.effective_cost_ms - rr.measured_cost_ms
            bits.append(f"→ ranked {rr.effective_cost_ms:.1f}ms ({delta:+.1f})")
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
    if name == "pia":
        return await PIAProvider().fetch_relays(cache)
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


def _sample_across_countries(relays: list[Relay], k: int) -> list[Relay]:
    """Pick up to k relays spread over as many distinct countries as possible.

    Used when the user's location is unknown: without coordinates there is no
    meaningful "nearest", so cover the map broadly and let measurement decide.
    Deterministic, so two runs on the same network are comparable.
    """
    if k <= 0:
        return []
    by_cc: dict[str, list[Relay]] = {}
    for r in relays:
        by_cc.setdefault((r.country_code or "").lower(), []).append(r)
    for group in by_cc.values():
        group.sort(key=lambda r: r.hostname)

    out: list[Relay] = []
    depth = 0
    while len(out) < k:
        added = False
        for cc in sorted(by_cc):
            group = by_cc[cc]
            if depth >= len(group):
                continue
            out.append(group[depth])
            added = True
            if len(out) >= k:
                break
        if not added:
            break
        depth += 1
    return out


# Below this, two relays are not distinguishable by a handful of packets even
# if neither showed any jitter at all.
MIN_NOISE_MS = 2.0


def _statistical_ties(reachable: list) -> list:
    """Relays this measurement cannot tell apart from the fastest one.

    Printing one winner implies we can distinguish it from the runner-up. Over
    five packets on a jittery link we often cannot, and saying so is more
    useful than presenting an arbitrary tiebreak as a result.

    Deliberately compares *measured* cost. The claim is about what the network
    told us, so folding in provider load, preference and history would let a
    policy penalty masquerade as a distinguishable measurement. The noise band
    takes whichever of the two relays measured less steadily, because a
    candidate with wide spread of its own is just as indistinguishable.
    """
    measured = [rr for rr in reachable if rr.measured_cost_ms is not None]
    if not measured:
        return list(reachable[:1])
    best = min(measured, key=lambda rr: rr.measured_cost_ms)
    best_jitter = best.probe.jitter_ms or 0.0
    return [
        rr for rr in measured
        if rr.measured_cost_ms - best.measured_cost_ms
        <= max(MIN_NOISE_MS, best_jitter, rr.probe.jitter_ms or 0.0)
    ]


def _fleet_size(relays: list[Relay], fallback: int) -> int:
    """The provider's real fleet size, not the size of the pool we kept.

    NordVPN's inventory is reduced by `spread()` before it reaches us, so
    counting what arrived would present a sample of ~8600 servers as if 500
    were the whole fleet.
    """
    for r in relays:
        size = r.metadata.get(NORDVPN_FLEET_SIZE_FIELD)
        if isinstance(size, int) and size > fallback:
            return size
    return fallback


def _why_unreachable(pairs, reachable_count: int) -> str:
    """Name the dominant failure when a provider yields nothing.

    Otherwise `--probe openvpn` makes Mullvad — which has no OpenVPN fleet —
    vanish from the results looking like a network fault.
    """
    if reachable_count or not pairs:
        return ""
    errors = [p.error for _r, p in pairs if p.error]
    if not errors:
        return ""
    return f" ({max(set(errors), key=errors.count)})"


def _selection_note(selected: int, available: int, detail: list[str]) -> str:
    """Say how much of the provider's fleet is actually being measured.

    A ranking over 30 of 587 relays is a different claim from a ranking over
    all of them, and the output should not let those two look alike.
    """
    head = f"{selected} of {available} probed"
    return f"{head} ({', '.join(detail)})" if detail else head


async def _gather_candidates(
    name: str,
    country_filter: str | None,
    geo: GeoContext,
    cfg,
    cache: JsonCache,
    nearby_ccs: list[str],
    scope: str = SCOPE_NEARBY,
    in_country_k: int = 60,
    relays_per_nearby_country: int = 1,
    fallback_neighbor_k: int = 8,
    global_sample_k: int = 40,
) -> tuple[list[tuple[Relay, str]], str]:
    """Return (list of (relay, source-tag), human-readable note).

    `scope` decides how far to look:
      here    — only the detected country
      nearby  — the detected country plus the nearest other countries
      global  — plus a spread of relays across every country served

    `nearby_ccs` is a pre-computed list of the geographically-nearest *other*
    countries (from a centroid table built from the union of provider relay
    coords). For each we sample `relays_per_nearby_country` nearest relays,
    querying NordVPN per-country if the global cached set lacks that country.
    """
    detected_cc = (country_filter or "").lower()
    # NordVPN's inventory is fetched country-filtered when we know where the
    # user is, which keeps the payload small and the local set deep. Under
    # `global` that filter is the opposite of what was asked for — the
    # worldwide sampler would only ever see the one country it was handed —
    # so `global` fetches both and unions them: "also sample every country"
    # means *also*, not *instead*.
    local_country_id = None
    if name == "nordvpn" and detected_cc:
        local_country_id = country_code_to_id(
            await fetch_countries(cache), detected_cc
        )
    target_country_id = None if scope == SCOPE_GLOBAL else local_country_id

    all_relays = await _provider_full_set(name, cache, target_country_id)
    if scope == SCOPE_GLOBAL and local_country_id is not None:
        seen = {(r.provider, r.id) for r in all_relays}
        all_relays = all_relays + [
            r for r in await _provider_full_set(name, cache, local_country_id)
            if (r.provider, r.id) not in seen
        ]
    all_relays = filter_relays(
        all_relays, country=None, city=None,
        protocol=cfg.defaults.feature, active_only=True, owned=None,
    )
    if not all_relays:
        return ([], "0 anywhere")
    fleet = _fleet_size(all_relays, len(all_relays))

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
        note_parts.append(f"nearest {len(picks)} in {detected_cc.upper()}")
    elif scope == SCOPE_HERE:
        # "here" means only my own country. Falling through to the recovery
        # branches below would quietly recommend an exit somewhere else, which
        # is precisely what the user ruled out.
        return ([], _selection_note(0, fleet, [
            f"none in {detected_cc.upper()} and scope is 'here'"
        ]))
    elif detected_cc:
        # No relays in detected country: fall back to nearest globally.
        recov = top_k_by_distance(
            all_relays, geo.latitude, geo.longitude, k=fallback_neighbor_k
        )
        for r in recov:
            selected.append((r, "nearest"))
        note_parts.append(f"0 in {detected_cc.upper()} → nearest {len(recov)}")
    elif geo.latitude is not None and geo.longitude is not None:
        # Coordinates but no country (e.g. STUN + coords override): distance
        # still ranks, so take the nearest relays anywhere.
        recov = top_k_by_distance(
            all_relays, geo.latitude, geo.longitude, k=fallback_neighbor_k
        )
        for r in recov:
            selected.append((r, "nearest"))
        note_parts.append(f"country unknown → nearest {len(recov)}")
    else:
        # Nothing known about location at all: geo lookup failed, or
        # `--lookup none` with no override. Returning nothing here is what
        # made the headline command exit 1 with relays already in hand.
        recov = _sample_across_countries(all_relays, k=fallback_neighbor_k * 2)
        for r in recov:
            selected.append((r, "sampled"))
        note_parts.append(f"location unknown → {len(recov)} sampled worldwide")

    already = {(r.provider, r.id) for r, _ in selected}

    if scope == SCOPE_GLOBAL:
        added_global = 0
        for r in _sample_across_countries(all_relays, k=global_sample_k):
            if (r.provider, r.id) in already:
                continue
            selected.append((r, "global"))
            already.add((r.provider, r.id))
            added_global += 1
        if added_global:
            note_parts.append(f"+{added_global} worldwide")

    if scope == SCOPE_HERE:
        return selected, _selection_note(len(selected), fleet, note_parts)

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
        for r in picks:
            if (r.provider, r.id) in already:
                continue
            selected.append((r, f"neighbor:{cc_l.upper()}"))
            already.add((r.provider, r.id))
            added_neighbors += 1

    if added_neighbors:
        note_parts.append(f"+{added_neighbors} from nearby countries")
    if missing_neighbors:
        note_parts.append(f"none in {','.join(missing_neighbors)}")

    return selected, _selection_note(len(selected), fleet, note_parts)


async def cmd_default(args: argparse.Namespace) -> int:
    """Headline action: detect context → preferred providers → best + alternatives + nearby."""
    cfg = load_config()
    _warn_config(cfg)
    cache = _cache_from_args(args)
    human = not args.json and not args.quiet

    def status(message: str = "") -> None:
        # Research narration is progress, not result. It used to go to stdout
        # in human mode, so `nearest-exit | tail -1` returned chatter.
        print(message, file=sys.stderr)

    vpn = _warn_if_tunnelled(args)

    probe_kind = args.probe or cfg.defaults.probe
    scope = args.scope or cfg.defaults.scope
    if scope not in SCOPE_CHOICES:
        scope = SCOPE_NEARBY
    override_country = args.country or cfg.geo.country
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
        cc = (geo.country_code or "").upper()
        country = geo.country_name or cc or "?"
        cc_suffix = f" ({cc})" if cc and geo.country_name else ""
        loc_str = f"{geo.city or '?'}, {country}{cc_suffix}"
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
        status(f"You: {' — '.join(bits)}  [geo: {geo.source}]")
    else:
        status(f"You: location unknown  [geo: {geo.source}]")

    country_filter = override_country or geo.country_code
    if scope == SCOPE_HERE and not country_filter:
        # "here" is meaningless without knowing where here is. Widening is
        # less surprising than returning nothing, but say so.
        print(
            "warning: --here needs a country and none could be determined; "
            "falling back to --nearby. Pass --country CC to scope it.",
            file=sys.stderr,
        )
        scope = SCOPE_NEARBY

    # An empty order means "no preference": probe everything and let the
    # measurement decide, rather than inventing a preference nobody asked for.
    pref_order = [p for p in cfg.providers.order if p in PROVIDER_NAMES]
    scan_order = list(pref_order)
    if cfg.providers.others_allowed or not pref_order:
        scan_order.extend(p for p in PROVIDER_NAMES if p not in scan_order)

    fp = network_fingerprint(geo.asn, geo.ip)
    winners = recent_winners(fp) if cfg.history.sticky else {}

    # Fetch provider relay sets first so country-centroid selection sees both
    # preferred providers and any allowed non-preferred recovery candidates.
    if pref_order:
        status(
            f"\nResearch: preferring {', '.join(pref_order)}, "
            f"location {loc_str or 'unknown'}"
        )
        extras = [p for p in scan_order if p not in pref_order]
        if extras:
            status(
                f"  other providers considered if they beat preferred by "
                f"{cfg.providers.others_threshold_ms:.1f}ms: {', '.join(extras)}"
            )
    else:
        status(
            f"\nResearch: no provider preference set, ranking on measurement "
            f"alone, location {loc_str or 'unknown'}"
        )
    if winners:
        status(
            f"  history is on: relays that won here before get up to "
            f"{STICKY_RTT_BONUS_CAP_MS:.0f}ms of head start"
        )
    if cfg.providers.penalties_ms:
        status(
            "  provider penalties: "
            + ", ".join(
                f"{name} +{ms:.1f}ms"
                for name, ms in sorted(cfg.providers.penalties_ms.items())
            )
        )
    if cfg.defaults.feature:
        status(f"  feature filter: {cfg.defaults.feature}")

    print("  fetching provider metadata…", file=sys.stderr)
    fetched_sets: dict[str, list[Relay]] = {}
    provider_errors: list[dict[str, str]] = []
    for name in scan_order:
        try:
            target_cid = None
            if name == "nordvpn" and country_filter and scope != SCOPE_GLOBAL:
                target_cid = country_code_to_id(
                    await fetch_countries(cache), country_filter
                )
            fetched_sets[name] = await _provider_full_set(name, cache, target_cid)
        except Exception as e:
            print(f"    {name}: fetch error: {e}", file=sys.stderr)
            provider_errors.append({"provider": name, "error": str(e)})
            fetched_sets[name] = []

    union_relays: list[Relay] = [r for rs in fetched_sets.values() for r in rs]
    centroids = merged_centroids(union_relays)
    cc_to_name: dict[str, str] = {}
    for r in union_relays:
        cc = (r.country_code or "").lower()
        if cc and r.country_name and cc not in cc_to_name:
            cc_to_name[cc] = r.country_name

    nearby_ccs = []
    if scope != SCOPE_HERE and geo.latitude is not None and geo.longitude is not None:
        # Only consider countries some provider actually serves. The embedded
        # centroid table covers the world, so unfiltered it spent neighbour
        # slots on places with no relays and then reported "none in BS,GL,GT".
        served = {
            (r.country_code or "").lower() for r in union_relays if r.country_code
        }
        nearby_ccs = [
            cc for cc, _d in nearest_countries(
                {cc: c for cc, c in centroids.items() if cc in served},
                geo.latitude, geo.longitude, k=6,
                exclude={(country_filter or "").lower()},
            )
        ]
    if nearby_ccs:
        labels = [
            f"{cc_to_name.get(cc.lower(), cc.upper())} ({cc.upper()})"
            for cc in nearby_ccs
        ]
        status(f"  nearest countries by centroid: {', '.join(labels)}")

    all_pairs: list[tuple[Relay, ProbeResult, str]] = []
    provider_notes: list[dict[str, str | int]] = []
    for name in scan_order:
        try:
            tagged, note = await _gather_candidates(
                name, country_filter, geo, cfg, cache,
                nearby_ccs=nearby_ccs, scope=scope,
                in_country_k=60, relays_per_nearby_country=1,
                fallback_neighbor_k=8,
            )
            status(f"  {name:<8} {note}")
            note_entry: dict[str, str | int] = {"provider": name, "note": note}
            if not tagged:
                provider_notes.append(note_entry)
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
                    show_progress=False, feature=cfg.defaults.feature,
                    probe_kind=probe_kind,
                )
                per_round_for_provider.append(round_pairs)
            if n_rounds > 1:
                pairs = merge_rounds(per_round_for_provider)
                ok = sum(1 for _, p in pairs if p.success)
                flap = sum(
                    1 for r, _ in pairs
                    if flappy(per_round_for_provider, r.id, provider=r.provider)
                )
                status(
                    f"             → probed {len(pairs)} × {n_rounds} rounds, "
                    f"reachable {ok}" + (f", flappy {flap}" if flap else "")
                    + _why_unreachable(pairs, ok)
                )
                note_entry.update({"probed": len(pairs), "rounds": n_rounds, "reachable": ok})
                if flap:
                    note_entry["flappy"] = flap
            else:
                pairs = per_round_for_provider[0]
                ok = sum(1 for _, p in pairs if p.success)
                status(
                    f"             → probed {len(pairs)}, reachable {ok}"
                    + _why_unreachable(pairs, ok)
                )
                note_entry.update({"probed": len(pairs), "rounds": n_rounds, "reachable": ok})
            for r, p in pairs:
                tag = tag_by_id.get(r.id, "")
                if n_rounds > 1 and flappy(per_round_for_provider, r.id, provider=r.provider):
                    tag = f"{tag} flappy" if tag else "flappy"
                all_pairs.append((r, p, tag))
            provider_notes.append(note_entry)
        except Exception as e:
            print(f"\n  {name}: error: {e}", file=sys.stderr)
            provider_errors.append({"provider": name, "error": str(e)})

    if not all_pairs:
        print("\nNo candidates probed. Try `nearest-exit doctor`.", file=sys.stderr)
        return 1

    tag_by_key = {(r.provider, r.id): src for r, _p, src in all_pairs}
    ranked = rank(
        [(r, p) for r, p, _src in all_pairs],
        provider_penalties=cfg.providers.penalties_ms,
        sticky_winners=winners,
    )
    ranked = apply_preference_threshold(
        ranked,
        pref_order,
        others_allowed=cfg.providers.others_allowed,
        others_threshold_ms=cfg.providers.others_threshold_ms,
    )
    reachable = [rr for rr in ranked if rr.probe.success]

    if not reachable:
        print("\nNo relays reachable from this network.", file=sys.stderr)
        return 1

    best_n = max(1, args.best)
    tied = _statistical_ties(reachable)
    # Naming one winner and then noting in parentheses that the winner is not
    # meaningful is a hedge, not a disclosure. When the measurement genuinely
    # cannot separate the leaders, the honest headline is that they are tied.
    undecided = len(tied) > best_n
    if undecided:
        best_slice = tied[:max(best_n, min(len(tied), args.alts + best_n))]
        label = (
            f"Tied ({len(tied)}) — measurement cannot separate these, "
            f"pick on any grounds you like:"
        )
    else:
        best_slice = reachable[:best_n]
        label = "Best:" if len(best_slice) == 1 else f"Best ({len(best_slice)}):"

    if args.quiet:
        # One bare name on stdout and nothing else, so the result can be piped
        # into a provider client or a WireGuard config generator. Everything
        # else this command prints — warnings, narration, the tie notice — is
        # already on stderr, so a caller reading stdout gets the answer or
        # nothing. A tie is deliberately not surfaced here: `--quiet` promises
        # exactly one line, and the caller asked for a decision rather than a
        # discussion. `--json` carries the tie for anyone who needs it.
        best = best_slice[0].relay
        print(best.hostname or best.ipv4 or best.id)
        return 0

    if human:
        print(f"\n{label}")
        for rr in best_slice:
            src = tag_by_key.get((rr.relay.provider, rr.relay.id), "")
            print(_fmt_relay_line(rr, src))
            if args.why:
                for reason in rr.reasons:
                    print(f"      · {reason}")
        if undecided and len(tied) > len(best_slice):
            print(f"  (…and {len(tied) - len(best_slice)} more, equally good)")

    # Alternatives: prefer provider diversity, then lowest cost.
    shown = {(rr.relay.provider, rr.relay.id) for rr in best_slice}
    seen_providers = {rr.relay.provider for rr in best_slice}
    diverse = []
    same_provider = []
    for rr in (rr for rr in reachable if (rr.relay.provider, rr.relay.id) not in shown):
        if rr.relay.provider not in seen_providers:
            diverse.append(rr)
            seen_providers.add(rr.relay.provider)
        else:
            same_provider.append(rr)
    alts = (diverse + same_provider)[: max(0, args.alts)]
    if human and alts:
        # Only worth explaining the ordering when it actually reorders.
        mixed = len({rr.relay.provider for rr in alts}) > 1
        print(
            "Alternatives (best of each other provider first):" if mixed
            else "Alternatives:"
        )
        for rr in alts:
            src = tag_by_key.get((rr.relay.provider, rr.relay.id), "")
            print(_fmt_relay_line(rr, src))
            if args.why:
                for reason in rr.reasons:
                    print(f"      · {reason}")

    # Nearby: best per *other* country (excludes the detected one). Selected on
    # measured cost, not raw RTT — picking on RTT here advertised a 10ms relay
    # dropping a third of its packets as a country's best, contradicting the
    # ranking directly above it.
    def _cost(rr) -> float:
        return rr.measured_cost_ms if rr.measured_cost_ms is not None else math.inf

    by_country: dict[str, object] = {}
    for rr in reachable:
        cc = (rr.relay.country_code or "").upper()
        if not cc or cc == (country_filter or "").upper():
            continue
        prev = by_country.get(cc)
        if prev is None or _cost(rr) < _cost(prev):
            by_country[cc] = rr
    nearby_items: list[dict] = []
    if by_country:
        baseline = _cost(best_slice[0])
        nearby = sorted(by_country.items(), key=lambda kv: _cost(kv[1]))[:5]
        bits = []
        for cc, rr in nearby:
            r, p = rr.relay, rr.probe
            delta = _cost(rr) - baseline
            sign = "+" if delta >= 0 else "-"
            label = r.country_name or cc
            bits.append(f"{label} ({cc}) {sign}{abs(delta):.0f}ms ({r.provider})")
            nearby_items.append({
                "country_code": cc,
                "country_name": r.country_name,
                "provider": r.provider,
                "relay_id": r.id,
                "hostname": r.hostname,
                "rtt_ms": p.rtt_ms,
                "measured_cost_ms": rr.measured_cost_ms,
                "delta_ms": delta,
            })
        if human:
            print(f"Nearby: {'   '.join(bits)}")

    # The rows the reader is actually invited to compare.
    if human and (note := _mixed_probe_note(best_slice + alts)):
        print(note)

    # Footer: how to reproduce.
    if human:
        status(f"\nProbed {len(all_pairs)} relays across {len(scan_order)} providers "
               f"(scope: {scope}). Use `nearest-exit scan --provider <name>` for "
               f"full per-provider rankings.")
    else:
        payload = {
            # Bumped whenever a field changes meaning or disappears, so a
            # consumer can fail loudly instead of misreading a renamed field.
            "schema_version": JSON_SCHEMA_VERSION,
            "geo": asdict(geo),
            "preferred_providers": pref_order,
            "scanned_providers": scan_order,
            "provider_notes": provider_notes,
            "provider_errors": provider_errors,
            "probed_relays": len(all_pairs),
            "scope": scope,
            # How many of the top relays this measurement cannot tell apart.
            "statistical_ties": len(tied),
            "best": [
                _ranked_json_item(
                    rr,
                    i,
                    tag_by_key.get((rr.relay.provider, rr.relay.id), ""),
                )
                for i, rr in enumerate(best_slice, 1)
            ],
            "alternatives": [
                _ranked_json_item(
                    rr,
                    i,
                    tag_by_key.get((rr.relay.provider, rr.relay.id), ""),
                )
                for i, rr in enumerate(alts, 1)
            ],
            "nearby": nearby_items,
        }
        print(json.dumps(payload, indent=2, default=str))

    # Record what we measured, not what we recommended. Writing back the
    # post-preference, post-history ordering made the whole thing
    # self-reinforcing: a preferred relay wins on policy, is recorded as the
    # winner, and gets a head start next time for having been preferred.
    measured_ranked = [
        rr for rr in rank([(r, p) for r, p, _src in all_pairs]) if rr.probe.success
    ]
    # Relays the measurement could not separate all share rank 1. Writing a
    # unique winner would hand the history bonus to whichever of them won a
    # coin flip, which is the flapping the bonus exists to prevent.
    measured_tied = {
        (rr.relay.provider, rr.relay.id) for rr in _statistical_ties(measured_ranked)
    }
    rows = []
    for i, rr in enumerate(measured_ranked[:HISTORY_RECORD_TOP], 1):
        r, p = rr.relay, rr.probe
        rows.append({
            "provider": r.provider,
            "relay_id": r.id,
            "hostname": r.hostname,
            "country_code": r.country_code,
            "rtt_ms": p.rtt_ms,
            "loss": p.loss,
            "jitter_ms": p.jitter_ms,
            "success": p.success,
            "rank": 1 if (r.provider, r.id) in measured_tied else i,
        })
    try:
        record_scan(rows, fp)
    except Exception as e:
        print(f"warning: could not record history: {e}", file=sys.stderr)

    return 0


def _relay_matches(relay: Relay, wanted: str) -> bool:
    return wanted in {(relay.hostname or "").lower(), (relay.id or "").lower()}


# NordVPN labels its British relays `uk...` while its own country list calls
# them GB, so the hostname's code cannot be handed straight to the lookup.
_HOSTNAME_CC_ALIASES = {"uk": "gb"}

# Big enough that spread() returns a country's inventory whole. The per-country
# inventory is cached without the limit in its key, so asking for all of one
# country costs the same fetch as asking for a sample of it.
_EXPLAIN_COUNTRY_LIMIT = 10_000


def _nordvpn_country_hint(name: str) -> str | None:
    """The country code buried in a NordVPN hostname, e.g. `ad10.nordvpn.com`.

    NordVPN's cached inventory is a `spread()` sample of a ~8600-server fleet,
    so a relay named on the command line is usually *not* in it. The hostname
    says which country to fetch, turning that miss into one targeted request.

    Two things the obvious implementation gets wrong. Some hostnames name two
    countries — `ca-us100` is a *US* relay reached via a Canadian entry — and
    it is the last group that says where the relay is: across the live
    inventory the last group matched the relay's own country 14 times out of
    18, the first only once. And `ch-onion2` has no country in its last group
    at all, so a two-letter first group is the fallback.
    """
    if not name.endswith(".nordvpn.com"):
        return None
    groups = re.findall(r"[a-z]+", name.split(".", 1)[0].lower())
    for candidate in (groups[-1:] + groups[:1]) if groups else []:
        if len(candidate) == 2:
            return _HOSTNAME_CC_ALIASES.get(candidate, candidate)
    return None


async def _find_relay(wanted: str, cache: JsonCache) -> tuple[Relay | None, bool]:
    """Locate a relay by hostname or id across every provider.

    Returns (relay, searched), where `searched` is False when not a single
    provider inventory could be read. Without that, an outage reported itself
    as "no relay named X", blaming the name for a network failure.
    """
    searched = False
    for name in PROVIDER_NAMES:
        try:
            relays = await _provider_full_set(name, cache, None)
        except Exception as e:
            print(f"warning: {name}: fetch failed: {e}", file=sys.stderr)
            continue
        searched = True
        for relay in relays:
            if _relay_matches(relay, wanted):
                return relay, True
    if cc := _nordvpn_country_hint(wanted):
        try:
            for relay in await _nordvpn_for_country(cc, cache, limit=_EXPLAIN_COUNTRY_LIMIT):
                searched = True
                if _relay_matches(relay, wanted):
                    return relay, True
        except Exception:
            pass
    return None, searched


async def cmd_explain(args: argparse.Namespace) -> int:
    """Probe one named relay and show what it costs and where it would rank.

    `--why` explains relays that already won a place in a result, which cannot
    answer the question people actually ask — "why not *this* one?". Ranking a
    named relay means probing the field it competes against too, so this costs
    about what a normal run costs.
    """
    cfg = load_config()
    _warn_config(cfg)
    cache = _cache_from_args(args)
    wanted = args.relay.strip().lower()

    def status(message: str = "") -> None:
        print(message, file=sys.stderr)

    _warn_if_tunnelled(args)

    status(f"Looking for {wanted}…")
    relay, searched = await _find_relay(wanted, cache)
    if relay is None:
        print(
            f"No relay named {args.relay!r} in any provider's inventory. "
            f"Hostnames and relay ids both work (e.g. de-ber-wg-001, "
            f"ad10.nordvpn.com)."
            if searched else
            "Could not read any provider's inventory, so there was nothing to "
            "search. Check connectivity, or retry without --no-cache.",
            file=sys.stderr,
        )
        return 1

    where = ", ".join(
        b for b in (relay.city, (relay.country_code or "").upper()) if b
    )
    status(f"Found {relay.hostname} — {relay.provider}{f', {where}' if where else ''}")

    probe_kind = args.probe or cfg.defaults.probe
    scope = args.scope or cfg.defaults.scope
    if scope not in SCOPE_CHOICES:
        scope = SCOPE_NEARBY

    override_coords: tuple[float, float] | None = None
    if args.coords:
        override_coords = (float(args.coords[0]), float(args.coords[1]))
    elif cfg.geo.coords:
        override_coords = cfg.geo.coords
    override_country = args.country or cfg.geo.country
    geo = await asyncio.to_thread(
        resolve_geo,
        args.lookup or cfg.geo.lookup,
        override_country,
        override_coords,
        cfg.geo.mmdb_path,
    )
    country_filter = override_country or geo.country_code
    fp = network_fingerprint(geo.asn, geo.ip)
    winners = recent_winners(fp) if cfg.history.sticky else {}

    # The field it competes against: the candidates the recommendation would
    # have considered from this relay's own provider. Comparing against every
    # provider would mix in preference policy and answer a different question.
    peers: list[Relay] = []
    try:
        full = await _provider_full_set(relay.provider, cache, None)
        nearby_ccs: list[str] = []
        if scope != SCOPE_HERE and geo.latitude is not None and geo.longitude is not None:
            served = {(r.country_code or "").lower() for r in full if r.country_code}
            centroids = merged_centroids(full)
            nearby_ccs = [
                cc for cc, _d in nearest_countries(
                    {cc: c for cc, c in centroids.items() if cc in served},
                    geo.latitude, geo.longitude, k=6,
                    exclude={(country_filter or "").lower()},
                )
            ]
        tagged, note = await _gather_candidates(
            relay.provider, country_filter, geo, cfg, cache,
            nearby_ccs=nearby_ccs, scope=scope,
        )
        peers = [r for r, _tag in tagged]
        status(f"  field: {note}")
    except Exception as e:
        status(f"  could not build a comparison set ({e}); measuring alone")

    field = [
        r for r in peers if (r.provider, r.id) != (relay.provider, relay.id)
    ] + [relay]
    status(f"  probing {len(field)} relay{'s' if len(field) != 1 else ''}…")
    pairs = await probe_all(
        field, concurrency=80, count=cfg.defaults.count,
        timeout_s=cfg.defaults.timeout, enable_tcp_fallback=True,
        show_progress=False, feature=cfg.defaults.feature, probe_kind=probe_kind,
    )
    ranked = rank(
        pairs,
        provider_penalties=cfg.providers.penalties_ms,
        sticky_winners=winners,
    )
    mine = next(
        (rr for rr in ranked
         if (rr.relay.provider, rr.relay.id) == (relay.provider, relay.id)),
        None,
    )
    if mine is None:
        print(f"{relay.hostname} could not be probed.", file=sys.stderr)
        return 1

    print(f"\n{relay.hostname} — {relay.provider}{f', {where}' if where else ''}")
    p = mine.probe
    if not p.success:
        print(f"  unreachable    {p.error or 'no reply'} (probe {p.probe})")
        print("  ranked         not ranked — a relay that does not answer "
              "cannot be compared")
        return 1

    loss_pct = f"{p.loss * 100:.0f}%" if p.loss is not None else "?"
    jitter = f"{p.jitter_ms:.1f}ms" if p.jitter_ms is not None else "?"
    print(f"  probe          {p.probe} → {p.target}")
    attempts = f"{p.attempts} attempt{'' if p.attempts == 1 else 's'}"
    print(f"  measured       {p.rtt_ms:.1f}ms, {loss_pct} loss over "
          f"{attempts}, jitter {jitter}")
    if mine.measured_cost_ms is not None:
        print(f"  measured cost  {mine.measured_cost_ms:.1f}ms")
    if mine.effective_cost_ms is not None:
        print(f"  ranked cost    {mine.effective_cost_ms:.1f}ms")
    for reason in mine.reasons:
        print(f"      · {reason}")

    reachable = [rr for rr in ranked if rr.probe.success]
    position = next(
        (i for i, rr in enumerate(reachable, start=1)
         if (rr.relay.provider, rr.relay.id) == (relay.provider, relay.id)),
        None,
    )
    if position is not None and reachable:
        best = reachable[0]
        print(
            f"\n  Ranks {position} of {len(reachable)} reachable "
            f"{relay.provider} relays considered here."
        )
        if position > 1 and best.effective_cost_ms is not None \
                and mine.effective_cost_ms is not None:
            gap = mine.effective_cost_ms - best.effective_cost_ms
            print(
                f"  {gap:.1f}ms behind {best.relay.hostname} "
                f"({best.effective_cost_ms:.1f}ms)."
            )
            if mine in _statistical_ties(reachable):
                print(
                    "  That gap is inside the measurement noise, so this relay "
                    "and the winner are not actually distinguishable."
                )
            # This comparison is exactly two rows, so a probe mismatch between
            # them undermines the one number this command exists to print.
            if note := _mixed_probe_note([mine, best]):
                print(f"  {note}")
    return 0


LIST_CHOICES = ("countries", "cities", "providers", "protocols")


def _list_rows(what: str, sets: dict[str, list[Relay]], country: str | None,
               extra_countries: dict[str, str]) -> tuple[list[str], list[list[str]]]:
    """Aggregate normalized relay metadata into (columns, rows)."""
    if what == "providers":
        cols = ["provider", "relays", "fleet", "countries", "cities", "protocols"]
        rows = []
        for name in sorted(sets):
            relays = sets[name]
            fleet = _fleet_size(relays, len(relays))
            rows.append([
                name,
                str(len(relays)),
                str(fleet) if fleet != len(relays) else "—",
                str(len({(r.country_code or "").lower() for r in relays if r.country_code})),
                # Keyed by (country, city) to match `list cities`. On name
                # alone, Berlin DE and Berlin US collapse into one.
                str(len({
                    ((r.country_code or "").lower(), r.city)
                    for r in relays if r.city
                })),
                ", ".join(sorted({p.lower() for r in relays for p in r.protocols})),
            ])
        return cols, rows

    if what == "protocols":
        cols = ["protocol", "relays", "providers"]
        counts: dict[str, int] = {}
        by_provider: dict[str, set[str]] = {}
        for name, relays in sets.items():
            for r in relays:
                for proto in r.protocols:
                    key = proto.lower()
                    counts[key] = counts.get(key, 0) + 1
                    by_provider.setdefault(key, set()).add(name)
        rows = [
            [proto, str(counts[proto]), ", ".join(sorted(by_provider[proto]))]
            for proto in sorted(counts, key=lambda k: (-counts[k], k))
        ]
        return cols, rows

    if what == "cities":
        cols = ["country", "city", "relays", "providers"]
        counts = {}
        by_provider = {}
        for name, relays in sets.items():
            for r in relays:
                if not r.city:
                    continue
                cc = (r.country_code or "").upper()
                if country and cc != country.upper():
                    continue
                key = (cc, r.city)
                counts[key] = counts.get(key, 0) + 1
                by_provider.setdefault(key, set()).add(name)
        rows = [
            [cc, city, str(counts[(cc, city)]), ", ".join(sorted(by_provider[(cc, city)]))]
            for cc, city in sorted(counts)
        ]
        return cols, rows

    cols = ["country", "code", "relays", "providers"]
    counts = {}
    names: dict[str, str] = {}
    by_provider = {}
    for name, relays in sets.items():
        for r in relays:
            cc = (r.country_code or "").lower()
            if not cc:
                continue
            counts[cc] = counts.get(cc, 0) + 1
            by_provider.setdefault(cc, set()).add(name)
            if r.country_name and cc not in names:
                names[cc] = r.country_name
    # Countries a provider serves but our inventory did not sample. Leaving
    # them out would answer "what countries exist?" with a sample, which is
    # the specific mistake this command exists to help diagnose.
    for cc, label in extra_countries.items():
        counts.setdefault(cc, 0)
        names.setdefault(cc, label)
        by_provider.setdefault(cc, set()).add("nordvpn")
    rows = [
        [names.get(cc, "?"), cc.upper(), str(counts[cc]), ", ".join(sorted(by_provider[cc]))]
        for cc in sorted(counts, key=lambda k: names.get(k, k))
    ]
    return cols, rows


async def cmd_list(args: argparse.Namespace) -> int:
    """Read normalized relay metadata without probing anything.

    A discovery and debugging tool, which is exactly what you want when the
    tool has just told you that nothing matched your filters.
    """
    cfg = load_config()
    _warn_config(cfg)
    cache = _cache_from_args(args)
    names = (
        list(PROVIDER_NAMES) if args.provider in (None, "all") else [args.provider]
    )

    sets: dict[str, list[Relay]] = {}
    sampled: list[str] = []
    for name in names:
        try:
            relays = await _provider_full_set(name, cache, None)
        except Exception as e:
            print(f"warning: {name}: fetch failed: {e}", file=sys.stderr)
            continue
        sets[name] = relays
        if _fleet_size(relays, len(relays)) > len(relays):
            sampled.append(name)

    if not sets:
        print("No provider metadata could be fetched.", file=sys.stderr)
        return 1

    # `--country` narrows every listing, not only `cities`. A flag that is
    # accepted and then quietly ignored on three of four subcommands is the
    # same defect as documenting one that does not exist.
    wanted_cc = (args.country or "").lower() or None
    if wanted_cc:
        sets = {
            name: [r for r in relays if (r.country_code or "").lower() == wanted_cc]
            for name, relays in sets.items()
        }

    extra_countries: dict[str, str] = {}
    if args.what == "countries" and "nordvpn" in sets:
        try:
            for entry in await fetch_countries(cache):
                code = str(entry.get("code", "")).lower()
                if code and (wanted_cc is None or code == wanted_cc):
                    extra_countries[code] = str(entry.get("name") or code.upper())
        except Exception:
            pass

    cols, rows = _list_rows(args.what, sets, getattr(args, "country", None),
                            extra_countries)
    if not rows:
        print("Nothing matched.", file=sys.stderr)
        return 1

    for name in sampled:
        relays = sets[name]
        print(
            f"note: {name}'s inventory here is a {len(relays)}-relay sample of "
            f"{_fleet_size(relays, len(relays))}, so its counts are of the "
            f"sample rather than the fleet.",
            file=sys.stderr,
        )

    fmt = getattr(args, "format", None) or (JSON if args.json else TABLE)
    if fmt == JSON:
        keys = [c.replace(" ", "_") for c in cols]
        print(json.dumps(
            [dict(zip(keys, row, strict=True)) for row in rows], indent=2,
        ))
    else:
        print(render(cols, rows, fmt))
    return 0


async def cmd_history(args: argparse.Namespace) -> int:
    cfg = load_config()
    _warn_config(cfg)
    fp = None
    if not args.any_network:
        # Identifying "this network" needs the public IP and ASN, which means
        # a lookup. Say so, because a command that only reads a local database
        # should not silently reach out to the internet.
        print("resolving current network…", file=sys.stderr)
        geo = await asyncio.to_thread(
            resolve_geo, cfg.geo.lookup, cfg.geo.country,
            cfg.geo.coords, cfg.geo.mmdb_path,
        )
        fp = network_fingerprint(geo.asn, geo.ip)
    winners = recent_winners(fp, since_seconds=args.window * 86400)
    where = "any network" if fp is None else "this network"
    if not winners:
        print(f"no recorded winners on {where} in the last {args.window} day(s).")
        return 0
    label = "all networks" if fp is None else f"network fingerprint: {fp}"
    print(f"{label}  (last {args.window} day(s))")
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
    _warn_config(cfg)
    print(f"config:    {default_config_path()}  (exists={default_config_path().exists()})")
    print(f"order:     {cfg.providers.order or '(none — ranking on measurement alone)'}")
    print(f"penalties: {cfg.providers.penalties_ms or '(none)'}")
    print(f"others:    allowed={cfg.providers.others_allowed} "
          f"threshold_ms={cfg.providers.others_threshold_ms}")
    print(f"defaults:  scope={cfg.defaults.scope} feature={cfg.defaults.feature} "
          f"top={cfg.defaults.top} rounds={cfg.defaults.rounds} "
          f"count={cfg.defaults.count} timeout={cfg.defaults.timeout}")
    print(f"geo:       lookup={cfg.geo.lookup}")
    return 0


def _add_shared_flags(parser: argparse.ArgumentParser, suppress: bool = False) -> None:
    """Flags that mean the same thing wherever they appear.

    Subcommand copies default to SUPPRESS. argparse parses the subparser into
    the *same* namespace after the root parser, so an ordinary default there
    would silently overwrite what `nearest-exit --no-cache scan` had already
    set — the flag would appear to work and do nothing.
    """
    hide: dict = {"default": argparse.SUPPRESS} if suppress else {}
    parser.add_argument(
        "--cache-dir", metavar="PATH",
        help="Where to keep cached provider metadata. Defaults to "
             "$XDG_CACHE_HOME/nearest-exit.",
        **hide,
    )
    parser.add_argument(
        "--no-cache", action="store_true",
        help="Do not read or write the on-disk cache. Metadata is still "
             "reused within the run, so this does not multiply requests.",
        **hide,
    )
    parser.add_argument(
        "--ignore-vpn-route-warning", action="store_true",
        help="Silence the warning about measuring from inside a tunnel.",
        **hide,
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="nearest-exit")
    _add_shared_flags(p)
    p.add_argument("--country", metavar="CC",
                   help="Override detected country (ISO 3166-1 alpha-2, e.g. YE).")
    # Scope flags. `--here` previously took a country code, which contradicted
    # the documented meaning of "search only where I am"; use --country for
    # the override.
    p.add_argument("--scope", choices=SCOPE_CHOICES, default=None,
                   help="How far to look for candidates. Defaults to config.")
    p.add_argument("--here", dest="scope", action="store_const", const=SCOPE_HERE,
                   help="Only consider relays in your own country.")
    p.add_argument("--nearby", dest="scope", action="store_const", const=SCOPE_NEARBY,
                   help="Your country plus the nearest other countries (default).")
    p.add_argument("--global", dest="scope", action="store_const", const=SCOPE_GLOBAL,
                   help="Also sample relays across every country served.")
    p.add_argument("--coords", nargs=2, type=float, metavar=("LAT", "LON"),
                   help="Override detected coordinates.")
    p.add_argument("--lookup", choices=("ipinfo", "stun", "none"),
                   help="Override geo lookup mode for this run.")
    p.add_argument("--rounds", type=_non_negative_int, default=0,
                   help="Probe each relay N rounds; useful on flappy links "
                        "(Starlink POP shifts, mobile). Defaults to config.")
    p.add_argument("--best", type=_positive_int, default=1,
                   help="How many top relays to show as 'Best'. Default 1.")
    p.add_argument("--alts", type=_non_negative_int, default=3,
                   help="How many alternatives to show after Best. Default 3.")
    # Both replace the human report with something a script reads, so asking
    # for both is a contradiction rather than a preference.
    out = p.add_mutually_exclusive_group()
    out.add_argument("--json", action="store_true",
                     help="Print default recommendation as machine-readable JSON.")
    out.add_argument("--format", choices=FORMATS, default=None,
                     help="Output format for `scan` and `list`. Accepted here "
                          "so it works on either side of the subcommand.")
    out.add_argument("--quiet", "-q", action="store_true",
                     help="Print only the winning hostname, for piping into a "
                          "client or a config generator. Everything else goes "
                          "to stderr.")
    p.add_argument("--why", action="store_true",
                   help="Show how each recommended relay's ranked cost was built.")
    p.add_argument("--probe", choices=PROBE_CHOICES, default=None,
                   help="How to measure, as opposed to which relays qualify. "
                        "'auto' is ICMP, then IKEv2 where published, then a TCP "
                        "connect; 'openvpn' measures the VPN daemon itself. "
                        "Defaults to config.")
    p.set_defaults(func=cmd_default, _async=True)
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="Probe and rank relays.")
    s.add_argument("--provider", choices=SCAN_PROVIDER_CHOICES, default="mullvad")
    s.add_argument("--country", help="Country code or name.")
    s.add_argument("--city")
    s.add_argument("--protocol", help="e.g. wireguard, openvpn")
    s.add_argument("--technology", help="NordVPN technology id (e.g. wireguard_udp)")
    s.add_argument("--include-inactive", action="store_true")
    s.add_argument("--owned", action=argparse.BooleanOptionalAction, default=None)
    s.add_argument("--top", type=_positive_int, default=None,
                   help="Rows to print. Defaults to defaults.top from config.")
    s.add_argument("--count", type=_positive_int, default=None,
                   help="Packets per probe. Defaults to defaults.count.")
    s.add_argument("--timeout", type=_positive_float, default=None,
                   help="Per-probe timeout. Defaults to defaults.timeout.")
    s.add_argument("--concurrency", type=_positive_int, default=100)
    s.add_argument("--refresh", action="store_true")
    s.add_argument("--no-tcp-fallback", action="store_true",
                   help="Disable the fallback chain when ICMP fails, so every "
                        "row is ICMP or nothing. (Also disables the IKEv2 step.)")
    s.add_argument("--geofilter", type=_non_negative_int, default=0,
                   help="Probe only the K relays nearest to the detected location.")
    # SUPPRESS for the same reason as the shared flags: a normal default here
    # overwrites `nearest-exit --json scan`, which parsed fine and printed a
    # human table.
    s.add_argument("--json", action="store_true", default=argparse.SUPPRESS,
                   help="Shorthand for --format json.")
    s.add_argument("--format", choices=FORMATS, default=argparse.SUPPRESS,
                   help="Output format. 'csv' and 'markdown' keep stdout to "
                        "the data, so notes and warnings go to stderr.")
    s.add_argument("--why", action="store_true",
                   help="Show how each ranked cost was built.")
    s.add_argument("--probe", choices=PROBE_CHOICES, default=None,
                   help="How to measure. 'openvpn' talks to the VPN daemon "
                        "rather than the IP stack in front of it.")
    s.add_argument("--preferences", action="store_true",
                   help="Apply provider preferences from config. Off by "
                        "default so scan always shows measurement alone.")
    s.add_argument("-v", "--verbose", action="store_true")
    _add_shared_flags(s, suppress=True)
    s.set_defaults(func=cmd_scan, _async=True)

    e = sub.add_parser(
        "explain",
        help="Probe one named relay and show how it would rank.",
        description="Probe one named relay and show what it costs and where "
                    "it would have ranked. `--why` explains relays already in "
                    "a result; this answers 'why not this one?'.",
    )
    e.add_argument("relay", help="Hostname or relay id, e.g. ad10.nordvpn.com.")
    _add_shared_flags(e, suppress=True)
    e.set_defaults(func=cmd_explain, _async=True)

    ls = sub.add_parser(
        "list",
        help="List countries, cities, providers or protocols without probing.",
        description="Read normalized relay metadata without probing anything "
                    "— useful when a filter has just returned no relays.",
    )
    ls.add_argument("what", choices=LIST_CHOICES)
    ls.add_argument("--provider", choices=SCAN_PROVIDER_CHOICES, default=None,
                    help="Restrict to one provider. Defaults to all of them.")
    ls.add_argument("--country", metavar="CC",
                    help="Restrict the listing to one country.")
    ls.add_argument("--json", action="store_true", default=argparse.SUPPRESS,
                    help="Shorthand for --format json.")
    ls.add_argument("--format", choices=FORMATS, default=argparse.SUPPRESS)
    _add_shared_flags(ls, suppress=True)
    ls.set_defaults(func=cmd_list, _async=True)

    d = sub.add_parser("doctor", help="Show local diagnostics.")
    d.set_defaults(func=cmd_doctor, _async=False)

    h = sub.add_parser("history", help="Show recent winners on this network.")
    h.add_argument("--window", type=_positive_int, default=7, help="Days to look back.")
    h.add_argument("--any-network", action="store_true", dest="any_network",
                   help="Show winners across every network, skipping the "
                        "geo lookup needed to identify the current one.")
    h.set_defaults(func=cmd_history, _async=True)

    pr = sub.add_parser("prefs", help="View or initialize preferences.")
    # Without this, a bare `nearest-exit prefs` inherits the root parser's
    # defaults and silently runs a full internet scan instead.
    pr.set_defaults(func=cmd_prefs_show, _async=False)
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
