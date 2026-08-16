import pytest

from nearest_exit.models import ProbeResult, Relay
from nearest_exit.rounds import flappy, merge_rounds


def relay(rid: str, provider: str = "t") -> Relay:
    return Relay(provider=provider, id=rid, hostname=rid, ipv4="1.2.3.4")


def probe(rid: str, *, success: bool, rtt: float | None = None,
          loss: float | None = 0.0, samples: tuple[float, ...] = (),
          attempts: int = 0, kind: str = "icmp") -> ProbeResult:
    return ProbeResult(
        relay_id=rid, probe=kind, target="1.2.3.4",
        success=success, rtt_ms=rtt, loss=loss, jitter_ms=0.0,
        samples=samples, attempts=attempts,
    )


def test_merge_takes_median_of_round_medians():
    a = relay("a")
    rounds = [
        [(a, probe("a", success=True, rtt=10.0))],
        [(a, probe("a", success=True, rtt=20.0))],
        [(a, probe("a", success=True, rtt=14.0))],
    ]
    merged = merge_rounds(rounds)
    assert len(merged) == 1
    _, p = merged[0]
    assert p.success and p.rtt_ms == 14.0


def test_merge_marks_dead_when_no_round_succeeds():
    a = relay("a")
    rounds = [
        [(a, probe("a", success=False))],
        [(a, probe("a", success=False))],
    ]
    merged = merge_rounds(rounds)
    _, p = merged[0]
    assert not p.success
    assert p.loss == 1.0


def test_merge_one_success_is_still_success():
    a = relay("a")
    rounds = [
        [(a, probe("a", success=False))],
        [(a, probe("a", success=True, rtt=42.0))],
    ]
    _, p = merge_rounds(rounds)[0]
    assert p.success and p.rtt_ms == 42.0


def test_merge_keeps_same_id_from_different_providers_apart():
    # Relay ids are only unique within a provider; a shared id must not merge.
    a = relay("shared", provider="mullvad")
    b = relay("shared", provider="pia")
    rounds = [
        [(a, probe("shared", success=True, rtt=10.0)),
         (b, probe("shared", success=True, rtt=90.0))],
        [(a, probe("shared", success=True, rtt=12.0)),
         (b, probe("shared", success=True, rtt=94.0))],
    ]
    merged = merge_rounds(rounds)
    assert len(merged) == 2
    by_provider = {r.provider: p for r, p in merged}
    assert by_provider["mullvad"].rtt_ms == 11.0
    assert by_provider["pia"].rtt_ms == 92.0


def test_flappy_scoped_by_provider():
    stable = relay("shared", provider="mullvad")
    unstable = relay("shared", provider="pia")
    rounds = [
        [(stable, probe("shared", success=True, rtt=20.0)),
         (unstable, probe("shared", success=True, rtt=20.0))],
        [(stable, probe("shared", success=True, rtt=21.0)),
         (unstable, probe("shared", success=False))],
    ]
    assert not flappy(rounds, "shared", provider="mullvad")
    assert flappy(rounds, "shared", provider="pia")
    # Without a provider the two collapse and the stable one looks flappy.
    assert flappy(rounds, "shared")


def test_flappy_detects_mixed_success_failure():
    a = relay("a")
    rounds = [
        [(a, probe("a", success=True, rtt=10.0))],
        [(a, probe("a", success=False))],
        [(a, probe("a", success=True, rtt=12.0))],
    ]
    assert flappy(rounds, "a")


def test_flappy_detects_wide_rtt_spread():
    a = relay("a")
    rounds = [
        [(a, probe("a", success=True, rtt=10.0))],
        [(a, probe("a", success=True, rtt=200.0))],
    ]
    assert flappy(rounds, "a", threshold_ms=50.0)


def test_not_flappy_when_stable():
    a = relay("a")
    rounds = [
        [(a, probe("a", success=True, rtt=20.0))],
        [(a, probe("a", success=True, rtt=22.0))],
        [(a, probe("a", success=True, rtt=21.0))],
    ]
    assert not flappy(rounds, "a", threshold_ms=50.0)


def test_merge_weights_loss_by_packets_sent_not_by_round():
    """Rounds do not all send the same count: a failed ICMP round falls back to
    TCP with `max(2, count - 1)`. Averaging the per-round rates weighted a
    2-packet round like a 5-packet one and understated the loss."""
    a = relay("a")
    rounds = [
        # 5 ICMP packets, 4 replies -> 20% loss.
        [(a, probe("a", success=True, rtt=20.0, loss=0.2,
                   samples=(20.0,) * 4, attempts=5))],
        # 4 TCP attempts, 2 replies -> 50% loss.
        [(a, probe("a", success=True, rtt=25.0, loss=0.5,
                   samples=(25.0,) * 2, attempts=4, kind="tcp/443"))],
    ]

    _relay, merged = merge_rounds(rounds)[0]

    assert merged.attempts == 9
    assert len(merged.samples) == 6
    # 6 replies out of 9 packets, not the unweighted mean of 20% and 50%.
    assert merged.loss == pytest.approx(1 - 6 / 9)
    assert merged.loss != pytest.approx((0.2 + 0.5) / 2)


def test_merge_falls_back_to_averaging_when_attempts_are_unknown():
    a = relay("a")
    rounds = [
        [(a, probe("a", success=True, rtt=20.0, loss=0.2, samples=(20.0,)))],
        [(a, probe("a", success=True, rtt=25.0, loss=0.4, samples=(25.0,)))],
    ]

    _relay, merged = merge_rounds(rounds)[0]

    assert merged.attempts == 0
    assert merged.loss == pytest.approx(0.3)
