from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

# metadata['geo_precision'] values, most to least precise. Defined here rather
# than in countries.py so geofilter can read them without an import cycle.
#
# There is no "exact" tier because no provider publishes one: NordVPN is the
# only one that returns coordinates at all, and all 800 sampled servers across
# 30 cities share exactly one coordinate per city — London and Paris are
# byte-identical to Mullvad's independently published city table.
GEO_PRECISION_CITY = "city"
GEO_PRECISION_COUNTRY = "country"


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
    # How many packets/connections were actually sent. Loss only means
    # something relative to this, and it cannot be recovered from `samples`
    # and `loss` once rounds with different counts are merged.
    attempts: int = 0
    error: str | None = None


@dataclass(frozen=True)
class RankedRelay:
    relay: Relay
    probe: ProbeResult
    # What the path cost us, with quality penalties but no user preference.
    # Preference policy compares these so a preference is applied only once.
    measured_cost_ms: float | None = None
    # measured cost plus provider preference and history bonus: the number
    # relays are actually ordered by, and the one output must show.
    effective_cost_ms: float | None = None
    reasons: tuple[str, ...] = ()
