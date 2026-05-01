from nearest_exit.models import ProbeResult, Relay
from nearest_exit.scoring import rank


def relay(hostname: str) -> Relay:
    return Relay(provider="mullvad", id=hostname, hostname=hostname, ipv4="1.2.3.4")


def probe(rid: str, *, success: bool, rtt: float | None = None,
          loss: float | None = None, jitter: float | None = None,
          error: str | None = None) -> ProbeResult:
    return ProbeResult(
        relay_id=rid, probe="icmp", target="1.2.3.4",
        success=success, rtt_ms=rtt, loss=loss, jitter_ms=jitter,
        samples=(), error=error,
    )


def test_reachable_beats_unreachable():
    a = relay("a")
    b = relay("b")
    pairs = [
        (a, probe("a", success=False, error="timeout")),
        (b, probe("b", success=True, rtt=80.0, loss=0.0, jitter=2.0)),
    ]
    ranked = rank(pairs)
    assert ranked[0].relay.hostname == "b"
    assert ranked[1].relay.hostname == "a"


def test_lower_rtt_wins():
    a = relay("slow")
    b = relay("fast")
    pairs = [
        (a, probe("slow", success=True, rtt=80.0, loss=0.0, jitter=2.0)),
        (b, probe("fast", success=True, rtt=20.0, loss=0.0, jitter=2.0)),
    ]
    ranked = rank(pairs)
    assert ranked[0].relay.hostname == "fast"


def test_loss_breaks_close_rtt_tie():
    a = relay("clean")
    b = relay("lossy")
    pairs = [
        (a, probe("clean", success=True, rtt=30.0, loss=0.0, jitter=1.0)),
        (b, probe("lossy", success=True, rtt=30.0, loss=0.25, jitter=1.0)),
    ]
    ranked = rank(pairs)
    assert ranked[0].relay.hostname == "clean"


def test_deterministic_when_all_else_equal():
    a = relay("zzz")
    b = relay("aaa")
    pairs = [
        (a, probe("zzz", success=True, rtt=20.0, loss=0.0, jitter=1.0)),
        (b, probe("aaa", success=True, rtt=20.0, loss=0.0, jitter=1.0)),
    ]
    ranked = rank(pairs)
    assert [r.relay.hostname for r in ranked] == ["aaa", "zzz"]


def test_reasons_for_unreachable():
    a = relay("dead")
    pairs = [(a, probe("dead", success=False, error="timeout"))]
    ranked = rank(pairs)
    assert "unreachable" in ranked[0].reasons[0]
