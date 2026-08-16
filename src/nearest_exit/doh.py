from __future__ import annotations

import json
import threading
import time
import urllib.parse
import urllib.request

DOH_URL = "https://cloudflare-dns.com/dns-query"
USER_AGENT = "nearest-exit/0.0.1"

POSITIVE_TTL_S = 300.0
NEGATIVE_TTL_S = 30.0

_cache: dict[str, tuple[float, list[str]]] = {}
_cache_lock = threading.Lock()
# One lock per hostname, so concurrent probes for the same relay collapse into
# a single query. Without this the memo only helps *after* the first result
# lands, and a fan-out of tasks that all start together all miss and all ask.
_inflight: dict[str, threading.Lock] = {}


def clear_cache() -> None:
    """Drop the in-process resolver cache (tests, or a forced refresh)."""
    with _cache_lock:
        _cache.clear()
        _inflight.clear()


def _cached(hostname: str) -> list[str] | None:
    with _cache_lock:
        hit = _cache.get(hostname)
        if hit is not None and hit[0] > time.monotonic():
            return list(hit[1])
    return None


def _host_lock(hostname: str) -> threading.Lock:
    with _cache_lock:
        return _inflight.setdefault(hostname, threading.Lock())


def resolve_a(hostname: str, timeout: float = 5.0) -> list[str]:
    """Resolve A records via Cloudflare DoH (JSON API).

    Returns a list of IPv4 strings, possibly empty. Bypasses the system
    resolver entirely so a hijacked or geo-skewed local DNS cannot bias
    relay measurements.

    Results are memoized in-process, and concurrent lookups of the same
    hostname collapse into one query: callers reach this via asyncio.to_thread
    from many tasks that start together, so a plain memo would let them all
    miss and all ask. Failures expire quickly, so a transient DoH blip does
    not blank a relay for the rest of the run.
    """
    cached = _cached(hostname)
    if cached is not None:
        return cached

    with _host_lock(hostname):
        # Another thread may have resolved this while we waited for the lock.
        cached = _cached(hostname)
        if cached is not None:
            return cached

        qs = urllib.parse.urlencode({"name": hostname, "type": "A"})
        url = f"{DOH_URL}?{qs}"
        req = urllib.request.Request(
            url, headers={"User-Agent": USER_AGENT, "accept": "application/dns-json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
                payload = json.load(r)
            answers = payload.get("Answer") or []
            ips = [a["data"] for a in answers if a.get("type") == 1 and a.get("data")]
        except Exception:
            ips = []

        ttl = POSITIVE_TTL_S if ips else NEGATIVE_TTL_S
        with _cache_lock:
            _cache[hostname] = (time.monotonic() + ttl, ips)
        return list(ips)
