from __future__ import annotations

import math

from .models import ProbeResult, RankedRelay, Relay


def sort_key(item: tuple[Relay, ProbeResult]) -> tuple:
    """Lexicographic sort: reachable first, then lower RTT, lower loss, lower jitter.
    Ties broken by hostname for determinism."""
    relay, probe = item
    reachable = 0 if probe.success else 1
    rtt = probe.rtt_ms if probe.rtt_ms is not None else math.inf
    loss = probe.loss if probe.loss is not None else 1.0
    jitter = probe.jitter_ms if probe.jitter_ms is not None else math.inf
    return (reachable, rtt, loss, jitter, relay.hostname)


def rank(pairs: list[tuple[Relay, ProbeResult]]) -> list[RankedRelay]:
    ordered = sorted(pairs, key=sort_key)
    out: list[RankedRelay] = []
    for relay, probe in ordered:
        reasons: list[str] = []
        if not probe.success:
            reasons.append(f"unreachable ({probe.error or 'no reply'})")
        else:
            reasons.append(f"median RTT {probe.rtt_ms:.1f}ms")
            if probe.jitter_ms is not None:
                reasons.append(f"jitter {probe.jitter_ms:.1f}ms")
            if probe.loss:
                reasons.append(f"loss {probe.loss * 100:.0f}%")
            if relay.load is not None:
                reasons.append(f"provider load {relay.load:.0f}%")
        out.append(RankedRelay(relay=relay, probe=probe, reasons=tuple(reasons)))
    return out
