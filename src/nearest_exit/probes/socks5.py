from __future__ import annotations

import asyncio
import statistics
import time

from ..models import ProbeResult


async def _one_handshake(ip: str, port: int, timeout_s: float) -> float | None:
    start = time.perf_counter()
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout_s,
        )
        writer.write(b"\x05\x01\x00")
        await asyncio.wait_for(writer.drain(), timeout=timeout_s)
        resp = await asyncio.wait_for(reader.readexactly(2), timeout=timeout_s)
        if resp != b"\x05\x00":
            return None
    except (TimeoutError, OSError, asyncio.IncompleteReadError):
        return None
    finally:
        if writer is not None:
            try:
                writer.close()
                await writer.wait_closed()
            except (OSError, ConnectionError):
                pass
    return (time.perf_counter() - start) * 1000.0


async def socks5_probe(
    relay_id: str,
    ip: str,
    port: int = 1080,
    count: int = 3,
    timeout_s: float = 2.0,
    discard_first: bool = True,
) -> ProbeResult:
    samples: list[float] = []
    failures = 0
    for _ in range(count):
        rtt = await _one_handshake(ip, port, timeout_s)
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
        error = None
    else:
        rtt_med = None
        jitter = None
        loss = 1.0
        error = "socks5 handshake failed or timed out"

    return ProbeResult(
        relay_id=relay_id,
        probe=f"socks5/{port}",
        target=f"{ip}:{port}",
        success=success,
        rtt_ms=rtt_med,
        loss=loss,
        jitter_ms=jitter,
        samples=tuple(samples),
        error=error,
    )
