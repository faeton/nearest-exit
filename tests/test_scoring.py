import math

from nearest_exit.models import ProbeResult, Relay
from nearest_exit.scoring import (
    JITTER_WEIGHT,
    apply_preference_threshold,
    confident_loss,
    effective_cost_ms,
    measured_cost_ms,
    probe_cost_ms,
    rank,
)


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
          error: str | None = None, sent: int = 4) -> ProbeResult:
    """Build a probe whose `samples` are consistent with `loss` and `sent`.

    Loss is discounted by sample size, so tests must say how many packets
    were behind a loss figure for the number to mean anything.
    """
    replies = round(sent * (1.0 - (loss or 0.0)))
    return ProbeResult(
        relay_id=rid, probe="icmp", target="1.2.3.4",
        success=success, rtt_ms=rtt, loss=loss, jitter_ms=jitter,
        samples=tuple([rtt or 0.0] * replies), error=error,
    )


def test_reachable_beats_unreachable():
    a, b = relay("a"), relay("b")
    ranked = rank([
        (a, probe("a", success=False, error="timeout")),
        (b, probe("b", success=True, rtt=80.0, loss=0.0, jitter=2.0)),
    ])
    assert [rr.relay.hostname for rr in ranked] == ["b", "a"]
    assert ranked[1].measured_cost_ms is None
    assert ranked[1].effective_cost_ms is None


def test_lower_rtt_wins():
    ranked = rank([
        (relay("slow"), probe("slow", success=True, rtt=80.0, loss=0.0, jitter=2.0)),
        (relay("fast"), probe("fast", success=True, rtt=20.0, loss=0.0, jitter=2.0)),
    ])
    assert ranked[0].relay.hostname == "fast"


def test_loss_breaks_close_rtt_tie():
    ranked = rank([
        (relay("clean"), probe("clean", success=True, rtt=30.0, loss=0.0, jitter=1.0)),
        (relay("lossy"), probe("lossy", success=True, rtt=30.0, loss=0.25, jitter=1.0)),
    ])
    assert ranked[0].relay.hostname == "clean"


def test_deterministic_when_all_else_equal():
    ranked = rank([
        (relay("zzz"), probe("zzz", success=True, rtt=20.0, loss=0.0, jitter=1.0)),
        (relay("aaa"), probe("aaa", success=True, rtt=20.0, loss=0.0, jitter=1.0)),
    ])
    assert [r.relay.hostname for r in ranked] == ["aaa", "zzz"]


def test_reasons_for_unreachable():
    ranked = rank([(relay("dead"), probe("dead", success=False, error="timeout"))])
    assert "unreachable" in ranked[0].reasons[0]


def test_provider_load_breaks_close_tie():
    busy = relay("busy", provider="nordvpn", load=90.0)
    quiet = relay("quiet", provider="nordvpn", load=10.0)
    ranked = rank([
        (busy, probe("busy", success=True, rtt=30.0, loss=0.0, jitter=0.0)),
        (quiet, probe("quiet", success=True, rtt=30.0, loss=0.0, jitter=0.0)),
    ])
    assert ranked[0].relay.hostname == "quiet"


def test_sticky_history_can_break_close_tie():
    old_winner = relay("old-winner", provider="nordvpn")
    fresh = relay("fresh", provider="nordvpn")
    ranked = rank(
        [
            (fresh, probe("fresh", success=True, rtt=22.0, loss=0.0, jitter=0.0)),
            (old_winner, probe("old-winner", success=True, rtt=24.0, loss=0.0, jitter=0.0)),
        ],
        sticky_winners={("nordvpn", "old-winner"): 1},
    )
    assert ranked[0].relay.hostname == "old-winner"


# --- provider preference is absolute, and applied exactly once ---------------


def test_provider_penalty_preserves_preference_over_small_rtt_win():
    preferred = relay("preferred", provider="nordvpn")
    other = relay("other", provider="mullvad")
    ranked = rank(
        [
            (other, probe("other", success=True, rtt=25.0, loss=0.0, jitter=0.0)),
            (preferred, probe("preferred", success=True, rtt=30.0, loss=0.0, jitter=0.0)),
        ],
        provider_penalties={"nordvpn": 0.0, "mullvad": 10.0},
    )
    assert ranked[0].relay.hostname == "preferred"
    assert ranked[0].measured_cost_ms == 30.0
    assert ranked[0].effective_cost_ms == 30.0


def test_provider_penalty_is_absolute_not_latency_scaled():
    """A multiplicative weight meant 9ms on fibre and 86ms on satellite; the
    same preference must cost the same on both links."""
    preferred = relay("preferred", provider="nordvpn")
    other = relay("other", provider="mullvad")
    penalties = {"nordvpn": 0.0, "mullvad": 10.0}

    for base in (20.0, 600.0):
        ranked = rank(
            [
                (other, probe("other", success=True, rtt=base - 12.0, loss=0.0, jitter=0.0)),
                (preferred, probe("preferred", success=True, rtt=base, loss=0.0, jitter=0.0)),
            ],
            provider_penalties=penalties,
        )
        # 12ms faster beats a 10ms penalty at any absolute latency.
        assert ranked[0].relay.hostname == "other", base
        gap = ranked[0].effective_cost_ms - ranked[0].measured_cost_ms
        assert gap == 10.0


def test_ranked_relay_reports_measured_and_effective_separately():
    """Output used to print the raw RTT while ranking on a different number."""
    r = relay("r", provider="mullvad")
    ranked = rank(
        [(r, probe("r", success=True, rtt=20.0, loss=0.0, jitter=0.0))],
        provider_penalties={"mullvad": 8.6},
    )
    rr = ranked[0]
    assert rr.measured_cost_ms == 20.0
    assert rr.effective_cost_ms == 28.6
    assert any("ranked at 28.6ms" in reason for reason in rr.reasons)


def test_preference_threshold_ignores_provider_penalty():
    """The penalty already ran inside the cost; applying the threshold to the
    penalised number applied the same preference twice and dropped a relay
    that was genuinely faster."""
    preferred = relay("preferred", provider="nordvpn")
    other = relay("other", provider="mullvad")
    penalties = {"nordvpn": 0.0, "mullvad": 8.6}
    ranked = rank(
        [
            (other, probe("other", success=True, rtt=20.0, loss=0.0, jitter=0.0)),
            (preferred, probe("preferred", success=True, rtt=30.0, loss=0.0, jitter=0.0)),
        ],
        provider_penalties=penalties,
    )
    filtered = apply_preference_threshold(
        ranked, ["nordvpn"], others_allowed=True, others_threshold_ms=5.0,
    )
    # 20ms vs 30ms measured: a clear 10ms win, so it survives the 5ms margin.
    assert "other" in [rr.relay.hostname for rr in filtered]


def test_preference_threshold_filters_marginal_non_preferred_winner():
    preferred = relay("preferred", provider="nordvpn")
    other = relay("other", provider="mullvad")
    ranked = rank([
        (other, probe("other", success=True, rtt=28.0, loss=0.0, jitter=0.0)),
        (preferred, probe("preferred", success=True, rtt=30.0, loss=0.0, jitter=0.0)),
    ])
    filtered = apply_preference_threshold(
        ranked, ["nordvpn"], others_allowed=True, others_threshold_ms=5.0,
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
        ranked, ["nordvpn"], others_allowed=True, others_threshold_ms=5.0,
    )
    assert [rr.relay.hostname for rr in filtered] == ["other", "preferred"]


def test_no_preferred_providers_keeps_everything():
    ranked = rank([
        (relay("a", provider="pia"), probe("a", success=True, rtt=20.0, loss=0.0, jitter=0.0)),
    ])
    filtered = apply_preference_threshold(
        ranked, [], others_allowed=True, others_threshold_ms=5.0,
    )
    assert len(filtered) == 1


# --- loss is discounted by how much evidence there is ------------------------


def test_loss_is_discounted_for_small_samples():
    """One drop out of three reads as 33% loss but is weak evidence."""
    thin = probe("thin", success=True, rtt=20.0, loss=1 / 3, jitter=0.0, sent=3)
    thick = probe("thick", success=True, rtt=20.0, loss=1 / 3, jitter=0.0, sent=30)

    assert confident_loss(thin) < 1 / 3
    assert confident_loss(thin) < confident_loss(thick)
    assert probe_cost_ms(thin) < probe_cost_ms(thick)


def test_single_drop_does_not_outweigh_a_large_latency_gap():
    fast_one_drop = probe("fast", success=True, rtt=20.0, loss=0.25, jitter=0.0, sent=4)
    slow_clean = probe("slow", success=True, rtt=60.0, loss=0.0, jitter=0.0, sent=4)
    assert probe_cost_ms(fast_one_drop) < probe_cost_ms(slow_clean)


def test_sustained_loss_outranks_a_small_latency_win():
    lossy = probe("lossy", success=True, rtt=20.0, loss=0.2, jitter=0.0, sent=40)
    clean = probe("clean", success=True, rtt=30.0, loss=0.0, jitter=0.0, sent=40)
    assert probe_cost_ms(clean) < probe_cost_ms(lossy)


def test_zero_loss_costs_nothing():
    assert confident_loss(probe("p", success=True, rtt=20.0, loss=0.0)) == 0.0
    assert probe_cost_ms(probe("p", success=True, rtt=20.0, loss=0.0)) == 20.0


def test_jitter_contributes_at_its_documented_weight():
    p = probe("p", success=True, rtt=20.0, loss=0.0, jitter=10.0)
    assert probe_cost_ms(p) == 20.0 + JITTER_WEIGHT * 10.0


def test_unreachable_costs_infinity():
    r = relay("dead")
    p = probe("dead", success=False)
    assert math.isinf(probe_cost_ms(p))
    assert math.isinf(measured_cost_ms(p))
    assert math.isinf(effective_cost_ms(r, p))


def test_measured_cost_excludes_provider_reported_load():
    """Load is a number the provider hands us, not something we observed, so
    it must not sit inside the figure labelled 'measured'."""
    busy = relay("busy", provider="nordvpn", load=100.0)
    p = probe("busy", success=True, rtt=20.0, loss=0.0, jitter=0.0)

    assert measured_cost_ms(p) == 20.0
    assert effective_cost_ms(busy, p) > 20.0
    assert rank([(busy, p)])[0].measured_cost_ms == 20.0


def test_load_still_breaks_ties_in_the_effective_cost():
    busy = relay("busy", provider="nordvpn", load=90.0)
    quiet = relay("quiet", provider="nordvpn", load=10.0)
    p = probe("x", success=True, rtt=30.0, loss=0.0, jitter=0.0)
    ranked = rank([(busy, p), (quiet, p)])
    assert ranked[0].relay.hostname == "quiet"
