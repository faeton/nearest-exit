from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass(frozen=True)
class Relay:
    provider: str
    id: str
    hostname: str
    country_code: str | None = None
    country_name: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    ipv4: str | None = None
    ipv6: str | None = None
    protocols: tuple[str, ...] = ()
    active: bool | None = None
    owned: bool | None = None
    load: float | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ProbeResult:
    relay_id: str
    probe: str
    target: str
    success: bool
    rtt_ms: float | None
    loss: float | None
    jitter_ms: float | None
    samples: tuple[float, ...]
    error: str | None = None


@dataclass(frozen=True)
class RankedRelay:
    relay: Relay
    probe: ProbeResult
    reasons: tuple[str, ...] = ()
