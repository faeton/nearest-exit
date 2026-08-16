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
    loss is total replies over total packets sent, and samples is the
    concatenation of all per-round samples. A relay is `success` if any
    round was.

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
        all_samples: list[float] = []
        for p in probes:
            all_samples.extend(p.samples)
        # Rounds do not all send the same number of packets: an ICMP round
        # that fails falls back to TCP with a different count. Averaging the
        # per-round rates would weight a 2-packet round like a 5-packet one.
        attempts = sum(p.attempts for p in probes)
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
