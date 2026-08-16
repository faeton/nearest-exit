from __future__ import annotations

import asyncio
import re
import statistics
import sys

from ..models import ProbeResult

_PING_RE = re.compile(r"time[=<]([\d.]+)\s*ms")
# Both BSD and GNU ping label each reply with its sequence number, which is
# the only way to tell whether the reply that arrived first was the *first
# packet sent* or merely the first one that came back.
_PING_REPLY_RE = re.compile(r"icmp_seq[= ](\d+).*?time[=<]([\d.]+)\s*ms")

# BSD ping (macOS) numbers packets from 0, GNU ping (Linux) from 1.
FIRST_SEQ = 0 if sys.platform == "darwin" else 1


def parse_ping_output(output: str) -> list[float]:
    return [float(t) for t in _PING_RE.findall(output)]


def parse_ping_replies(output: str) -> list[tuple[int, float]]:
    """Return (sequence number, rtt_ms) for every reply, in output order.

    Empty when the platform's ping does not print sequence numbers (Windows),
    in which case callers fall back to `parse_ping_output`.
    """
    return [(int(seq), float(rtt)) for seq, rtt in _PING_REPLY_RE.findall(output)]


def warm_samples(
    replies: list[tuple[int, float]], first_seq: int = FIRST_SEQ
) -> list[float]:
    """Drop the reply to the very first packet, which pays for ARP and route
    setup. Only that packet is cold: if it was lost there is nothing to drop,
    and if a later packet was lost the cold one must still go."""
    warm = [rtt for seq, rtt in replies if seq != first_seq]
    return warm if warm else [rtt for _seq, rtt in replies]


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
    """ICMP probe. Sends `count` packets; RTT is the median of the warm replies.

    The first packet pays for ARP and route resolution, so it is discarded —
    but identified by its sequence number, not by its position among the
    replies. Discarding `samples[0]` threw away a warm sample whenever the
    cold packet was the one that got lost, and kept the cold one whenever a
    later packet was lost.
    """
    cmd = _build_cmd(ip, count, timeout_s)
    samples: list[float] = []
    replies: list[tuple[int, float]] = []
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
        except TimeoutError:
            proc.kill()
            await proc.communicate()
            error = "timeout"
            out = b""
        text = out.decode("utf-8", "ignore")
        replies = parse_ping_replies(text)
        samples = [rtt for _seq, rtt in replies] or parse_ping_output(text)
    except (OSError, TimeoutError) as e:
        error = str(e) or "error"

    if not discard_first:
        effective = samples
    elif replies:
        effective = warm_samples(replies)
    else:
        # No sequence numbers (Windows). Only a complete run proves the first
        # reply is the cold one.
        effective = samples[1:] if len(samples) == count >= 2 else samples

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
        attempts=count,
        error=error,
    )
