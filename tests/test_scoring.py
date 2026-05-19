from nearest_exit.models import ProbeResult, Relay
from nearest_exit.scoring import apply_preference_threshold, rank


def relay(hostname: str, *, provider: str = "mullvad", load: float | None = None) -> Relay:
    return Relay(
        provider=provider,
        id=hostname,
        hostname=hostname,
        ipv4="1.2.3.4",
        load=load,
    )


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


def test_provider_weight_can_preserve_preference_over_small_rtt_win():
    preferred = relay("preferred", provider="nordvpn")
    less_preferred = relay("less-preferred", provider="mullvad")
    pairs = [
        (less_preferred, probe("less-preferred", success=True, rtt=25.0, loss=0.0, jitter=0.0)),
        (preferred, probe("preferred", success=True, rtt=30.0, loss=0.0, jitter=0.0)),
    ]
    ranked = rank(pairs, provider_weights={"nordvpn": 1.0, "mullvad": 0.7})
    assert ranked[0].relay.hostname == "preferred"
    assert ranked[0].effective_rtt_ms == 30.0


def test_provider_load_breaks_close_tie():
    busy = relay("busy", provider="nordvpn", load=90.0)
    quiet = relay("quiet", provider="nordvpn", load=10.0)
    pairs = [
        (busy, probe("busy", success=True, rtt=30.0, loss=0.0, jitter=0.0)),
        (quiet, probe("quiet", success=True, rtt=30.0, loss=0.0, jitter=0.0)),
    ]
    ranked = rank(pairs)
    assert ranked[0].relay.hostname == "quiet"


def test_sticky_history_can_break_close_tie():
    old_winner = relay("old-winner", provider="nordvpn")
    fresh = relay("fresh", provider="nordvpn")
    pairs = [
        (fresh, probe("fresh", success=True, rtt=22.0, loss=0.0, jitter=0.0)),
        (old_winner, probe("old-winner", success=True, rtt=24.0, loss=0.0, jitter=0.0)),
    ]
    ranked = rank(pairs, sticky_winners={("nordvpn", "old-winner"): 1})
    assert ranked[0].relay.hostname == "old-winner"


def test_preference_threshold_filters_marginal_non_preferred_winner():
    preferred = relay("preferred", provider="nordvpn")
    other = relay("other", provider="mullvad")
    ranked = rank([
        (other, probe("other", success=True, rtt=28.0, loss=0.0, jitter=0.0)),
        (preferred, probe("preferred", success=True, rtt=30.0, loss=0.0, jitter=0.0)),
    ])
    filtered = apply_preference_threshold(
        ranked,
        ["nordvpn"],
        others_allowed=True,
        others_threshold_ms=5.0,
    )
    assert [rr.relay.hostname for rr in filtered] == ["preferred"]


def test_preference_threshold_keeps_clear_non_preferred_winner():
    preferred = relay("preferred", provider="nordvpn")
    other = relay("other", provider="mullvad")
    ranked = rank([
        (other, probe("other", success=True, rtt=20.0, loss=0.0, jitter=0.0)),
        (preferred, probe("preferred", success=True, rtt=30.0, loss=0.0, jitter=0.0)),
    ])
    filtered = apply_preference_threshold(
        ranked,
        ["nordvpn"],
        others_allowed=True,
        others_threshold_ms=5.0,
    )
    assert [rr.relay.hostname for rr in filtered] == ["other", "preferred"]
