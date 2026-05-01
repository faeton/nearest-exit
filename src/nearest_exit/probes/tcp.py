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
    except (asyncio.TimeoutError, OSError):
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
    samples after discarding the first (cold ARP/route)."""
    samples: list[float] = []
    error: str | None = None
    failures = 0
    for _ in range(count):
        rtt = await _one_connect(ip, port, timeout_s)
        if rtt is None:
            failures += 1
            continue
        samples.append(rtt)

    effective = samples[1:] if discard_first and len(samples) >= 2 else samples
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
