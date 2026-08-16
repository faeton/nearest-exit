from __future__ import annotations

import asyncio
import statistics
import time

from ..models import ProbeResult


async def _one_connect(ip: str, port: int, timeout_s: float) -> float | None:
    start = time.perf_counter()
    try:
        fut = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout_s)
    except (TimeoutError, OSError):
        return None
    rtt_ms = (time.perf_counter() - start) * 1000.0
    try:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ConnectionError):
            pass
    except Exception:
        pass
    return rtt_ms


def _warm_samples(attempts: list[float | None], discard_first: bool) -> list[float]:
    """Successful RTTs with the cold attempt dropped.

    The cold sample is whatever came back from the *first attempt*, not the
    first success: when the opening connect is lost, attempts[0] is None and
    there is nothing cold left to discard. Never returns empty when any
    attempt succeeded, so a single warm-up-only success still counts.
    """
    ok = [a for a in attempts if a is not None]
    if discard_first and attempts and attempts[0] is not None and len(ok) >= 2:
        return ok[1:]
    return ok


async def tcp_probe(
    relay_id: str,
    ip: str,
    port: int = 443,
    count: int = 3,
    timeout_s: float = 2.0,
    discard_first: bool = True,
) -> ProbeResult:
    """TCP-connect probe. Opens N short-lived TCP connections to (ip, port)
    sequentially, measures handshake time, closes immediately. Median over
    samples after discarding the first attempt (cold ARP/route)."""
    error: str | None = None
    attempts: list[float | None] = []
    for _ in range(count):
        attempts.append(await _one_connect(ip, port, timeout_s))

    samples = [a for a in attempts if a is not None]
    failures = len(attempts) - len(samples)
    effective = _warm_samples(attempts, discard_first)
    success = len(effective) > 0
    if success:
        rtt_med = statistics.median(effective)
        jitter = statistics.pstdev(effective) if len(effective) >= 2 else 0.0
        loss = failures / count
    else:
        rtt_med = None
        jitter = None
        loss = 1.0
        if failures == count:
            error = "tcp connect refused or timeout"

    return ProbeResult(
        relay_id=relay_id,
        probe=f"tcp/{port}",
        target=f"{ip}:{port}",
        success=success,
        rtt_ms=rtt_med,
        loss=loss,
        jitter_ms=jitter,
        samples=tuple(samples),
        error=error,
    )
