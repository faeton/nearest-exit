from __future__ import annotations

import json
import urllib.parse
import urllib.request

DOH_URL = "https://cloudflare-dns.com/dns-query"
USER_AGENT = "nearest-exit/0.0.1"


def resolve_a(hostname: str, timeout: float = 5.0) -> list[str]:
    """Resolve A records via Cloudflare DoH (JSON API).

    Returns a list of IPv4 strings, possibly empty. Bypasses the system
    resolver entirely so a hijacked or geo-skewed local DNS cannot bias
    relay measurements.
    """
    qs = urllib.parse.urlencode({"name": hostname, "type": "A"})
    url = f"{DOH_URL}?{qs}"
    req = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "accept": "application/dns-json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
            payload = json.load(r)
    except Exception:
        return []
    answers = payload.get("Answer") or []
    return [a["data"] for a in answers if a.get("type") == 1 and a.get("data")]
