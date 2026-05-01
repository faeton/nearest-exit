from __future__ import annotations

import asyncio
import re
import statistics
import sys

from ..models import ProbeResult

_PING_RE = re.compile(r"time[=<]([\d.]+)\s*ms")


def parse_ping_output(output: str) -> list[float]:
    return [float(t) for t in _PING_RE.findall(output)]


def _build_cmd(ip: str, count: int, timeout_s: float) -> list[str]:
    if sys.platform == "darwin":
        return ["ping", "-c", str(count), "-W", str(int(timeout_s * 1000)), ip]
    if sys.platform.startswith("linux"):
        return ["ping", "-c", str(count), "-W", str(max(1, int(timeout_s))), ip]
    return ["ping", "-n", str(count), "-w", str(int(timeout_s * count * 1000)), ip]


async def icmp_probe(
    relay_id: str,
    ip: str,
    count: int = 4,
    timeout_s: float = 2.0,
    discard_first: bool = True,
) -> ProbeResult:
    """ICMP probe. Sends `count` packets; if discard_first and >=2 samples returned,
    drops the first sample (cold ARP/route resolution). RTT is the median of remaining."""
    cmd = _build_cmd(ip, count, timeout_s)
    samples: list[float] = []
    error: str | None = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            out, _ = await asyncio.wait_for(
                proc.communicate(), timeout=(timeout_s + 1) * count
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            error = "timeout"
            out = b""
        samples = parse_ping_output(out.decode("utf-8", "ignore"))
    except (OSError, asyncio.TimeoutError) as e:
        error = str(e) or "error"

    effective = samples[1:] if discard_first and len(samples) >= 2 else samples
    success = len(effective) > 0
    if success:
        rtt = statistics.median(effective)
        jitter = statistics.pstdev(effective) if len(effective) >= 2 else 0.0
        loss = 1.0 - (len(samples) / count) if count else 0.0
    else:
        rtt = None
        jitter = None
        loss = 1.0

    return ProbeResult(
        relay_id=relay_id,
        probe="icmp",
        target=ip,
        success=success,
        rtt_ms=rtt,
        loss=loss,
        jitter_ms=jitter,
        samples=tuple(samples),
        error=error,
    )
