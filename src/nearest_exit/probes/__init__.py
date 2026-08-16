from __future__ import annotations

__all__ = ["probe_family", "summarise"]


def probe_family(probe: str) -> str:
    """What a probe label says was measured, ignoring which port it used.

    `ikev2/500` and `ikev2/4500` are the same measurement; `icmp` and
    `tcp/443` are not. Shared so the round merger and the mixed-probe
    disclosure cannot disagree about what counts as the same kind of number.
    """
    return (probe or "").split("/", 1)[0]


def summarise(
    attempts: list[float | None], discard_first: bool
) -> tuple[list[float], int, int]:
    """Split probe attempts into (warm samples, attempts counted, replies).

    Shared by every probe that measures per-attempt, so the warm-up rule means
    one thing across ICMP, OpenVPN and IKEv2.

    The first attempt pays for ARP and route setup — and over TCP for the
    connection itself — so it is excluded from the median *and* from the loss
    denominator. But only when a later attempt actually answered: excluding it
    when it is the sole reply produced a result that was successful and
    simultaneously reported 100% loss of the attempts it counted.
    """
    successes = [a for a in attempts if a is not None]
    warm = [a for a in attempts[1:] if a is not None]
    if discard_first and len(attempts) >= 2 and warm:
        return warm, len(attempts) - 1, len(warm)
    return successes, len(attempts), len(successes)
