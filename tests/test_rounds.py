from nearest_exit.models import ProbeResult, Relay
from nearest_exit.rounds import flappy, merge_rounds


def relay(rid: str) -> Relay:
    return Relay(provider="t", id=rid, hostname=rid, ipv4="1.2.3.4")


def probe(rid: str, *, success: bool, rtt: float | None = None,
          loss: float | None = 0.0, samples: tuple[float, ...] = ()) -> ProbeResult:
    return ProbeResult(
        relay_id=rid, probe="icmp", target="1.2.3.4",
        success=success, rtt_ms=rtt, loss=loss, jitter_ms=0.0,
        samples=samples,
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
