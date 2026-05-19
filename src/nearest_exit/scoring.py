from __future__ import annotations

import math
from collections.abc import Mapping, Sequence

from .models import ProbeResult, RankedRelay, Relay


def effective_rtt_ms(
    relay: Relay,
    probe: ProbeResult,
    provider_weights: Mapping[str, float] | None = None,
    sticky_ms: float = 0.0,
) -> float:
    """Return the recommendation cost in milliseconds.

    Lower is better. RTT remains the dominant signal; jitter, loss, and provider
    load add small explainable penalties. Provider weights and sticky history
    adjust the same cost rather than creating a second ranking path.
    """
    if not probe.success or probe.rtt_ms is None:
        return math.inf

    loss_penalty = (probe.loss or 0.0) * 100.0
    jitter_penalty = (probe.jitter_ms or 0.0) * 0.25
    load_penalty = (relay.load or 0.0) * 0.03
    raw = probe.rtt_ms + loss_penalty + jitter_penalty + load_penalty

    weight = 1.0
    if provider_weights is not None:
        weight = provider_weights.get(relay.provider, 1.0)
    return (raw / max(weight, 0.01)) - sticky_ms


def sort_key(
    item: tuple[Relay, ProbeResult],
    provider_weights: Mapping[str, float] | None = None,
    sticky_winners: Mapping[tuple[str, str], int] | None = None,
) -> tuple:
    """Reachable first, then lower shared recommendation cost.

    Ties are broken by hostname for deterministic output.
    """
    relay, probe = item
    reachable = 0 if probe.success else 1
    sticky = 0.0
    if sticky_winners:
        n = sticky_winners.get((relay.provider, relay.id), 0)
        sticky = min(3.0 * n, 8.0) if n > 0 else 0.0
    score = effective_rtt_ms(relay, probe, provider_weights, sticky)
    return (reachable, score, relay.hostname)


def rank(
    pairs: Sequence[tuple[Relay, ProbeResult]],
    provider_weights: Mapping[str, float] | None = None,
    sticky_winners: Mapping[tuple[str, str], int] | None = None,
) -> list[RankedRelay]:
    ordered = sorted(
        pairs,
        key=lambda item: sort_key(item, provider_weights, sticky_winners),
    )
    out: list[RankedRelay] = []
    for relay, probe in ordered:
        reasons: list[str] = []
        sticky = 0.0
        if sticky_winners:
            n = sticky_winners.get((relay.provider, relay.id), 0)
            sticky = min(3.0 * n, 8.0) if n > 0 else 0.0
        score = effective_rtt_ms(relay, probe, provider_weights, sticky)
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
            if provider_weights and provider_weights.get(relay.provider, 1.0) != 1.0:
                reasons.append(f"provider weight {provider_weights[relay.provider]:.2f}")
            if sticky:
                reasons.append(f"history bonus {sticky:.1f}ms")
        out.append(
            RankedRelay(
                relay=relay,
                probe=probe,
                effective_rtt_ms=None if math.isinf(score) else score,
                reasons=tuple(reasons),
            )
        )
    return out


def apply_preference_threshold(
    ranked: Sequence[RankedRelay],
    preferred_providers: Sequence[str],
    *,
    others_allowed: bool,
    others_threshold_ms: float,
) -> list[RankedRelay]:
    """Filter non-preferred relays according to user preference policy.

    Preferred providers are always kept. Other providers are kept only when
    enabled and they beat the best reachable preferred relay by the configured
    effective-millisecond margin. If no preferred relay is reachable, reachable
    non-preferred relays are allowed as a recovery path.
    """
    preferred = set(preferred_providers)
    if not preferred:
        return list(ranked)
    if not others_allowed:
        return [rr for rr in ranked if rr.relay.provider in preferred]

    preferred_reachable = [
        rr for rr in ranked
        if rr.relay.provider in preferred and rr.probe.success and rr.effective_rtt_ms is not None
    ]
    if not preferred_reachable:
        return [
            rr for rr in ranked
            if rr.relay.provider in preferred or rr.probe.success
        ]

    best_preferred = min(rr.effective_rtt_ms for rr in preferred_reachable)
    assert best_preferred is not None
    cutoff = best_preferred - max(0.0, others_threshold_ms)
    out: list[RankedRelay] = []
    for rr in ranked:
        if rr.relay.provider in preferred:
            out.append(rr)
        elif rr.probe.success and rr.effective_rtt_ms is not None and rr.effective_rtt_ms <= cutoff:
            out.append(rr)
    return out
