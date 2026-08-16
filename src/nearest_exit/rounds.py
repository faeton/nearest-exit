from __future__ import annotations

import statistics

from .models import ProbeResult, Relay
from .probes import probe_family


def merge_rounds(
    per_round: list[list[tuple[Relay, ProbeResult]]],
) -> list[tuple[Relay, ProbeResult]]:
    """Combine multiple round results per relay.

    For each relay, collapse per-round samples into one ProbeResult whose
    rtt_ms is the median across the per-round medians, jitter_ms is the
    pstdev of those round medians (a 'between-rounds' instability measure
    that captures Starlink-style POP shifts the per-round jitter misses),
    loss is total replies over total packets sent, and samples is the
    concatenation of all per-round samples. A relay is `success` if any
    round was.

    Only rounds that measured the same way are combined. `auto` picks its
    probe per round, so a relay can answer ICMP in one round and IKEv2 in the
    next; the family that measured it most often wins and the rest are left
    out rather than averaged into a number that happened in neither round.

    Keyed by (provider, id): relay ids are only unique within a provider —
    Mullvad uses hostnames, AirVPN public names, PIA region slugs, NordVPN
    numeric ids — so id alone would silently merge two providers' samples.
    """
    if not per_round:
        return []
    by_id: dict[tuple[str, str], tuple[Relay, list[ProbeResult]]] = {}
    for round_pairs in per_round:
        for r, p in round_pairs:
            entry = by_id.get((r.provider, r.id))
            if entry is None:
                by_id[(r.provider, r.id)] = (r, [p])
            else:
                entry[1].append(p)

    out: list[tuple[Relay, ProbeResult]] = []
    for (_provider, rid), (relay, probes) in by_id.items():
        successes = [p for p in probes if p.success and p.rtt_ms is not None]
        contributing = probes
        if successes:
            # Rounds do not have to agree on *how* they measured. `auto` falls
            # through per round, so a relay whose ICMP flaps can answer ICMP in
            # one round and IKEv2 in the next. Taking the median across those
            # produced a number that occurred in neither round — 10ms ICMP and
            # 70ms IKEv2 became "icmp 40ms" — and labelled it with whichever
            # family happened to come first, which also hid the mixture from
            # the mixed-probe disclosure downstream.
            #
            # Keep the family that measured this relay most often and report
            # that alone. Rounds measured another way are not averaged in: they
            # are a different quantity, and the point of rounds is to reduce
            # noise rather than to blend measurements.
            by_family: dict[str, list[ProbeResult]] = {}
            for p in successes:
                by_family.setdefault(probe_family(p.probe), []).append(p)
            # Most rounds wins, then most samples. The family name is the last
            # term purely so ties are deterministic — it is not a preference,
            # and it does not need to be: whichever family wins, the reported
            # number is one real measurement rather than a blend of two.
            family = max(
                by_family,
                key=lambda f: (
                    len(by_family[f]),
                    sum(len(p.samples) for p in by_family[f]),
                    f,
                ),
            )
            successes = by_family[family]
            # Failed rounds of the same family still count against it: an ICMP
            # round that answered nothing is an ICMP measurement that lost
            # everything, and dropping it would flatter the loss figure.
            contributing = [p for p in probes if probe_family(p.probe) == family]

        all_samples: list[float] = []
        for p in contributing:
            all_samples.extend(p.samples)
        # Rounds do not all send the same number of packets: an ICMP round
        # that fails falls back to TCP with a different count. Averaging the
        # per-round rates would weight a 2-packet round like a 5-packet one.
        attempts = sum(p.attempts for p in contributing)
        if successes:
            rtts = [p.rtt_ms for p in successes]
            rtt_med = statistics.median(rtts)
            jitter = statistics.pstdev(rtts) if len(rtts) >= 2 else (
                successes[0].jitter_ms or 0.0
            )
            if attempts > 0:
                loss = max(0.0, 1.0 - len(all_samples) / attempts)
            else:
                losses = [p.loss for p in probes if p.loss is not None]
                loss = sum(losses) / len(losses) if losses else 0.0
            target = successes[0].target
            probe_kind = successes[0].probe
            success = True
            error = None
        else:
            rtt_med = None
            jitter = None
            loss = 1.0
            target = probes[0].target
            probe_kind = probes[0].probe
            success = False
            error = next((p.error for p in probes if p.error), "all rounds failed")

        out.append((
            relay,
            ProbeResult(
                relay_id=rid,
                probe=probe_kind,
                target=target,
                success=success,
                rtt_ms=rtt_med,
                loss=loss,
                jitter_ms=jitter,
                samples=tuple(all_samples),
                attempts=attempts,
                error=error,
            ),
        ))
    return out


def flappy(
    per_round: list[list[tuple[Relay, ProbeResult]]],
    relay_id: str,
    threshold_ms: float = 50.0,
    provider: str | None = None,
) -> bool:
    """A relay is 'flappy' if its per-round RTT spread exceeds `threshold_ms`
    or if some rounds succeeded and others failed.

    Pass `provider` whenever `per_round` can hold more than one provider —
    relay ids collide across providers. Omitting it matches on id alone.
    """
    rtts: list[float] = []
    successes = 0
    failures = 0
    for round_pairs in per_round:
        for r, p in round_pairs:
            if r.id != relay_id or (provider is not None and r.provider != provider):
                continue
            if p.success and p.rtt_ms is not None:
                rtts.append(p.rtt_ms)
                successes += 1
            else:
                failures += 1
    if successes and failures:
        return True
    if len(rtts) >= 2 and (max(rtts) - min(rtts)) > threshold_ms:
        return True
    return False
