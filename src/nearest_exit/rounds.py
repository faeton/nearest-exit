from __future__ import annotations

import statistics

from .models import ProbeResult, Relay


def merge_rounds(
    per_round: list[list[tuple[Relay, ProbeResult]]],
) -> list[tuple[Relay, ProbeResult]]:
    """Combine multiple round results per relay.

    For each relay, collapse per-round samples into one ProbeResult whose
    rtt_ms is the median across the per-round medians, jitter_ms is the
    pstdev of those round medians (a 'between-rounds' instability measure
    that captures Starlink-style POP shifts the per-round jitter misses),
    loss is the average per-round loss, and samples is the concatenation
    of all per-round samples. A relay is `success` if any round was.
    """
    if not per_round:
        return []
    by_id: dict[str, tuple[Relay, list[ProbeResult]]] = {}
    for round_pairs in per_round:
        for r, p in round_pairs:
            entry = by_id.get(r.id)
            if entry is None:
                by_id[r.id] = (r, [p])
            else:
                entry[1].append(p)

    out: list[tuple[Relay, ProbeResult]] = []
    for rid, (relay, probes) in by_id.items():
        successes = [p for p in probes if p.success and p.rtt_ms is not None]
        all_samples: list[float] = []
        for p in probes:
            all_samples.extend(p.samples)
        if successes:
            rtts = [p.rtt_ms for p in successes]
            rtt_med = statistics.median(rtts)
            jitter = statistics.pstdev(rtts) if len(rtts) >= 2 else (
                successes[0].jitter_ms or 0.0
            )
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
                error=error,
            ),
        ))
    return out


def flappy(
    per_round: list[list[tuple[Relay, ProbeResult]]],
    relay_id: str,
    threshold_ms: float = 50.0,
) -> bool:
    """A relay is 'flappy' if its per-round RTT spread exceeds `threshold_ms`
    or if some rounds succeeded and others failed."""
    rtts: list[float] = []
    successes = 0
    failures = 0
    for round_pairs in per_round:
        for r, p in round_pairs:
            if r.id != relay_id:
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
