from __future__ import annotations

import math
from collections.abc import Mapping, Sequence

from .history import sticky_bonus
from .models import ProbeResult, RankedRelay, Relay

# Every penalty below is expressed in milliseconds of equivalent latency, so
# the final number stays readable as "this path costs about N ms".

# Packet loss. The linear term makes any loss matter; the quadratic term makes
# a badly lossy relay lose outright rather than trading a few milliseconds.
# At a confident 5% loss a relay must be ~22ms faster to still win.
LOSS_LINEAR_MS = 300.0
LOSS_QUADRATIC_MS = 3000.0

# Two-sided 95% z-score, used to discount loss observed over few packets.
LOSS_CONFIDENCE_Z = 1.96

# Jitter is a real cost for interactive traffic but should not outrank latency
# outright, so it counts for half of what the same number of milliseconds of
# median RTT would.
JITTER_WEIGHT = 0.5

# Provider-reported load is a tiebreaker, not a ranking signal: a fully loaded
# relay costs 3ms, about the width of a measurement.
LOAD_PENALTY_MS_PER_PERCENT = 0.03


def _attempts(probe: ProbeResult) -> int:
    """How many packets a loss figure is based on.

    Probes record this directly. The fallback inverts it from samples and
    loss, which is exact for a single probe but wrong for merged rounds that
    sent different counts, so it is only for hand-built results.
    """
    if probe.attempts > 0:
        return probe.attempts
    replies = len(probe.samples)
    loss = probe.loss or 0.0
    if replies == 0 or loss >= 1.0:
        return max(replies, 1)
    return max(replies, round(replies / (1.0 - loss)))


def confident_loss(probe: ProbeResult) -> float:
    """Lower bound of the Wilson score interval for this probe's loss rate.

    Penalising the observed rate directly overreacts at the packet counts this
    tool uses: one drop out of three reads as 33% loss but is weak evidence of
    a bad path. Asking instead "how much loss are we actually confident about"
    makes a single drop cost a few milliseconds while a relay that keeps
    dropping packets is still ranked out.
    """
    loss = probe.loss or 0.0
    if loss <= 0.0:
        return 0.0
    n = _attempts(probe)
    if n <= 0:
        return loss
    z2 = LOSS_CONFIDENCE_Z ** 2
    centre = loss + z2 / (2 * n)
    spread = LOSS_CONFIDENCE_Z * math.sqrt(loss * (1.0 - loss) / n + z2 / (4 * n * n))
    lower = (centre - spread) / (1.0 + z2 / n)
    return max(0.0, min(lower, loss))


def loss_penalty_ms(probe: ProbeResult) -> float:
    p = confident_loss(probe)
    return LOSS_LINEAR_MS * p + LOSS_QUADRATIC_MS * p * p


def probe_cost_ms(probe: ProbeResult) -> float:
    """Relay-independent measurement cost for one probe, in milliseconds.

    Used to compare several probe targets belonging to the same relay, where
    provider load is identical and only measurement quality differs.
    """
    if not probe.success or probe.rtt_ms is None:
        return math.inf
    return (
        probe.rtt_ms
        + loss_penalty_ms(probe)
        + JITTER_WEIGHT * (probe.jitter_ms or 0.0)
    )


def measured_cost_ms(probe: ProbeResult) -> float:
    """What this network measured for this relay, and nothing else.

    Deliberately excludes provider-reported load. Load is a number the
    provider hands us, not something we observed from here, and this is both
    the value the preference threshold compares and the one the output calls
    "measured" — so it has to contain only measurement.
    """
    return probe_cost_ms(probe)


def load_penalty_ms(relay: Relay) -> float:
    return LOAD_PENALTY_MS_PER_PERCENT * (relay.load or 0.0)


def effective_cost_ms(
    relay: Relay,
    probe: ProbeResult,
    provider_penalties: Mapping[str, float] | None = None,
    sticky_ms: float = 0.0,
) -> float:
    """Measured cost plus everything that is not measurement. Lower is better.

    That means provider-reported load, the user's provider preference, and
    the history bonus. Provider penalties are absolute milliseconds, not
    multipliers, so "I prefer NordVPN by 10ms" means the same thing on a 20ms
    fibre link and on a 600ms satellite link.
    """
    base = measured_cost_ms(probe)
    if math.isinf(base):
        return base
    penalty = 0.0
    if provider_penalties:
        penalty = float(provider_penalties.get(relay.provider, 0.0))
    return base + load_penalty_ms(relay) + penalty - sticky_ms


def _sticky_ms(
    relay: Relay, sticky_winners: Mapping[tuple[str, str], int] | None
) -> float:
    if not sticky_winners:
        return 0.0
    return sticky_bonus(relay.provider, relay.id, sticky_winners)


def sort_key(
    item: tuple[Relay, ProbeResult],
    provider_penalties: Mapping[str, float] | None = None,
    sticky_winners: Mapping[tuple[str, str], int] | None = None,
) -> tuple:
    """Reachable first, then lower effective cost.

    Ties are broken by hostname for deterministic output.
    """
    relay, probe = item
    reachable = 0 if probe.success else 1
    score = effective_cost_ms(
        relay, probe, provider_penalties, _sticky_ms(relay, sticky_winners)
    )
    return (reachable, score, relay.hostname)


def _reasons(
    relay: Relay,
    probe: ProbeResult,
    measured: float,
    effective: float,
    penalty: float,
    sticky: float,
) -> tuple[str, ...]:
    if not probe.success:
        return (f"unreachable ({probe.error or 'no reply'})",)

    out = [f"median RTT {probe.rtt_ms:.1f}ms"]
    if probe.jitter_ms:
        out.append(
            f"jitter {probe.jitter_ms:.1f}ms (+{JITTER_WEIGHT * probe.jitter_ms:.1f}ms)"
        )
    if probe.loss:
        confident = confident_loss(probe)
        out.append(
            f"loss {probe.loss * 100:.0f}% over {_attempts(probe)} "
            f"(+{loss_penalty_ms(probe):.1f}ms)"
        )
        if confident < probe.loss:
            out.append(f"loss discounted to {confident * 100:.1f}% for sample size")
    out.append(f"measured cost {measured:.1f}ms")
    if relay.load:
        out.append(
            f"provider-reported load {relay.load:.0f}% "
            f"(+{load_penalty_ms(relay):.1f}ms, not measured here)"
        )
    if penalty:
        out.append(f"provider preference {penalty:+.1f}ms")
    if sticky:
        out.append(f"previous winner here {-sticky:+.1f}ms")
    if effective != measured:
        out.append(f"ranked at {effective:.1f}ms")
    return tuple(out)


def rank(
    pairs: Sequence[tuple[Relay, ProbeResult]],
    provider_penalties: Mapping[str, float] | None = None,
    sticky_winners: Mapping[tuple[str, str], int] | None = None,
) -> list[RankedRelay]:
    ordered = sorted(
        pairs,
        key=lambda item: sort_key(item, provider_penalties, sticky_winners),
    )
    out: list[RankedRelay] = []
    for relay, probe in ordered:
        sticky = _sticky_ms(relay, sticky_winners)
        penalty = (
            float(provider_penalties.get(relay.provider, 0.0))
            if provider_penalties else 0.0
        )
        measured = measured_cost_ms(probe)
        effective = effective_cost_ms(relay, probe, provider_penalties, sticky)
        out.append(
            RankedRelay(
                relay=relay,
                probe=probe,
                measured_cost_ms=None if math.isinf(measured) else measured,
                effective_cost_ms=None if math.isinf(effective) else effective,
                reasons=_reasons(relay, probe, measured, effective, penalty, sticky),
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
    margin. If no preferred relay is reachable, reachable non-preferred relays
    are allowed as a recovery path.

    The comparison uses *measured* cost, never effective cost. Comparing
    already-preference-adjusted numbers applied the same preference twice and
    dropped relays that were genuinely faster.
    """
    preferred = set(preferred_providers)
    if not preferred:
        return list(ranked)
    if not others_allowed:
        return [rr for rr in ranked if rr.relay.provider in preferred]

    preferred_reachable = [
        rr for rr in ranked
        if rr.relay.provider in preferred and rr.probe.success
        and rr.measured_cost_ms is not None
    ]
    if not preferred_reachable:
        return [
            rr for rr in ranked
            if rr.relay.provider in preferred or rr.probe.success
        ]

    best_preferred = min(rr.measured_cost_ms for rr in preferred_reachable)
    cutoff = best_preferred - max(0.0, others_threshold_ms)
    out: list[RankedRelay] = []
    for rr in ranked:
        if rr.relay.provider in preferred:
            out.append(rr)
        elif (
            rr.probe.success
            and rr.measured_cost_ms is not None
            and rr.measured_cost_ms <= cutoff
        ):
            out.append(rr)
    return out
