from __future__ import annotations

import math
import os
import tomllib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# The providers this build knows about. Penalties are relative, so normalising
# them requires knowing who is implicitly at zero.
KNOWN_PROVIDERS = ("mullvad", "nordvpn", "airvpn", "pia")


def default_config_path() -> Path:
    if env := os.environ.get("NEAREST_EXIT_CONFIG"):
        return Path(env)
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "nearest-exit" / "config.toml"


@dataclass
class ProvidersConfig:
    # Empty means "no provider preference": probe everything, rank purely by
    # measurement. Listing every provider here is the same as listing none,
    # except that it also disables `others_threshold_ms`.
    order: list[str] = field(default_factory=list)
    # Milliseconds added to a provider's measured cost before ranking. Empty
    # by default: with no config, ranking is pure measurement.
    penalties_ms: dict[str, float] = field(default_factory=dict)
    others_allowed: bool = True
    others_threshold_ms: float = 5.0  # non-preferred must beat preferred by this many ms


@dataclass
class DefaultsConfig:
    feature: str | None = None  # e.g. "wireguard" — filters which relays qualify
    # How to measure, which is a different question from which relays qualify.
    probe: str = "auto"          # auto | icmp | tcp | openvpn | socks5
    # "nearby" matches both the shipped config and what the default flow has
    # always actually done; the old "here" default was never read by anything.
    scope: str = "nearby"        # here | nearby | global
    top: int = 3
    rounds: int = 1
    # Five packets, not three. Loss is only meaningful relative to how many
    # were sent, and at n=3 a single drop reads as 33% — enough noise to
    # reorder the table on its own.
    count: int = 5
    timeout: float = 2.0


@dataclass
class HistoryConfig:
    # Off by default. A relay that won here before gets a head start, which
    # helps the same relay win again — useful as anti-flap, but it is not
    # measurement, so the tool should not do it unless asked.
    sticky: bool = False


@dataclass
class GeoConfig:
    lookup: str = "ipinfo"        # ipinfo | stun | none
    country: str | None = None    # manual override, ISO 3166-1 alpha-2
    coords: tuple[float, float] | None = None  # manual (lat, lon) override
    mmdb_path: str | None = None  # optional MaxMind GeoLite2-City .mmdb


@dataclass
class Config:
    providers: ProvidersConfig = field(default_factory=ProvidersConfig)
    defaults: DefaultsConfig = field(default_factory=DefaultsConfig)
    geo: GeoConfig = field(default_factory=GeoConfig)
    history: HistoryConfig = field(default_factory=HistoryConfig)
    # Problems found while reading the file. Kept on the object so a bad config
    # surfaces as a warning at the top of a run instead of a traceback.
    load_errors: list[str] = field(default_factory=list)


# A provider preference is a dial, not an override. Allowing arbitrarily large
# values lets one provider win regardless of measurement, which defeats the
# point of measuring; cap it where the dial still has to argue.
MAX_PENALTY_MS = 200.0

# Legacy multiplicative `weights` are converted to millisecond penalties at
# this reference latency. Multiplicative weights were the bug: the same
# setting meant 9ms on a fibre link and 86ms on a satellite one.
LEGACY_WEIGHT_REFERENCE_MS = 30.0


def _as_float(value: Any, key: str, errors: list[str]) -> float | None:
    """Coerce a TOML scalar to a finite float, recording why if it cannot."""
    if isinstance(value, bool):
        errors.append(f"{key}: expected a number, got boolean {value!r} — ignored")
        return None
    quoted = False
    if isinstance(value, int | float):
        out = float(value)
    elif isinstance(value, str):
        try:
            out = float(value.strip())
        except ValueError:
            errors.append(f"{key}: expected a number, got {value!r} — ignored")
            return None
        quoted = True
    else:
        errors.append(f"{key}: expected a number, got {type(value).__name__} — ignored")
        return None
    if not math.isfinite(out):
        errors.append(f"{key}: must be a finite number, got {value!r} — ignored")
        return None
    if quoted:
        errors.append(f"{key}: {value!r} is quoted; remove the quotes (read as {out})")
    return out


def _as_int(value: Any, key: str, errors: list[str]) -> int | None:
    out = _as_float(value, key, errors)
    if out is None:
        return None
    if out != int(out):
        errors.append(f"{key}: expected a whole number, got {value!r} — rounded down")
    return int(out)


def _as_bool(value: Any, key: str, errors: list[str]) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        low = value.strip().lower()
        if low in {"true", "yes", "on", "1"}:
            errors.append(f"{key}: {value!r} is quoted; use bare true")
            return True
        if low in {"false", "no", "off", "0"}:
            errors.append(f"{key}: {value!r} is quoted; use bare false")
            return False
    errors.append(f"{key}: expected true or false, got {value!r} — ignored")
    return None


def _as_str(value: Any, key: str, errors: list[str]) -> str | None:
    if isinstance(value, str):
        return value
    errors.append(f"{key}: expected a string, got {type(value).__name__} — ignored")
    return None


def validate_config(
    cfg: Config,
    valid_providers: Iterable[str],
) -> list[str]:
    """Return human-readable configuration warnings.

    Validation is intentionally non-fatal: a typo should be visible, but should
    not stop a one-off scan from running with the valid parts. Values are
    already coerced and range-checked by `load_config`, so this only reports
    what is semantically wrong rather than guarding against wrong types.
    """
    warnings: list[str] = list(cfg.load_errors)
    providers = set(valid_providers)

    unknown_order = [p for p in cfg.providers.order if p not in providers]
    if unknown_order:
        warnings.append(
            "unknown provider(s) in providers.order: "
            + ", ".join(sorted(set(unknown_order)))
        )

    unknown_penalties = [p for p in cfg.providers.penalties_ms if p not in providers]
    if unknown_penalties:
        warnings.append(
            "unknown provider(s) in providers.penalties_ms: "
            + ", ".join(sorted(set(unknown_penalties)))
        )

    for provider, ms in cfg.providers.penalties_ms.items():
        if not isinstance(ms, int | float) or isinstance(ms, bool) or not math.isfinite(ms):
            warnings.append(f"providers.penalties_ms.{provider} must be a finite number")

    if cfg.providers.others_threshold_ms < 0:
        warnings.append("providers.others_threshold_ms must be >= 0")

    # The threshold only governs providers that are *not* in `order`, so
    # listing everything silently turns the whole preference system off.
    if (
        cfg.providers.others_threshold_ms
        and providers
        and providers.issubset(set(cfg.providers.order))
    ):
        warnings.append(
            "providers.order lists every provider, so providers.others_threshold_ms "
            "has no effect — remove the ones you do not actually prefer"
        )

    if cfg.defaults.scope not in {"here", "nearby", "global"}:
        warnings.append("defaults.scope must be one of: here, nearby, global")

    if cfg.defaults.probe not in {"auto", "icmp", "tcp", "openvpn", "socks5"}:
        warnings.append(
            "defaults.probe must be one of: auto, icmp, tcp, openvpn, socks5"
        )

    if cfg.defaults.top < 1:
        warnings.append("defaults.top must be >= 1")
    if cfg.defaults.rounds < 1:
        warnings.append("defaults.rounds must be >= 1")
    if cfg.defaults.count < 1:
        warnings.append("defaults.count must be >= 1")
    if cfg.defaults.timeout <= 0:
        warnings.append("defaults.timeout must be > 0")

    if cfg.geo.lookup not in {"ipinfo", "stun", "none"}:
        warnings.append("geo.lookup must be one of: ipinfo, stun, none")

    return warnings


def _read_penalties(raw: Any, key: str, errors: list[str]) -> dict[str, float]:
    if not isinstance(raw, dict):
        errors.append(f"{key}: expected a table — ignored")
        return {}
    out: dict[str, float] = {}
    for name, value in raw.items():
        ms = _as_float(value, f"{key}.{name}", errors)
        if ms is not None:
            out[name] = ms
    return out


def _convert_legacy_weights(raw: Any, errors: list[str]) -> dict[str, float]:
    """Translate the removed multiplicative `weights` into ms penalties.

    Weights divided the cost, so their effect grew with absolute latency and
    the same setting behaved differently on every link. Converting at a fixed
    reference latency keeps existing configs working while making the value
    mean one thing.
    """
    if not isinstance(raw, dict):
        errors.append("providers.weights: expected a table — ignored")
        return {}
    out: dict[str, float] = {}
    for name, value in raw.items():
        w = _as_float(value, f"providers.weights.{name}", errors)
        if w is None:
            continue
        if w <= 0:
            errors.append(f"providers.weights.{name}: must be > 0, got {w} — ignored")
            continue
        out[name] = LEGACY_WEIGHT_REFERENCE_MS * (1.0 / w - 1.0)
    return out


def normalize_penalties(
    raw: Mapping[str, float], known_providers: Iterable[str]
) -> dict[str, float]:
    """Turn relative penalties into a complete, anchored, bounded table.

    Three things have to happen in this order:

    1. Every known provider gets an entry. Unlisted providers are implicitly
       at zero, so shifting only the listed ones would change their relation
       to the unlisted ones — `weights = { nordvpn = 2.0 }` used to convert to
       a single -15ms entry, get shifted to 0, and lose the preference
       entirely.
    2. Anchor the most-preferred provider at zero, so the winner's ranked
       number equals its measured cost and only the gaps matter.
    3. Clamp *after* anchoring. Clamping first let {-1e9, +1e9} become
       {-200, +200} and then anchor to a 400ms spread, twice the stated limit.
    """
    if not raw:
        return {}
    full = {name: 0.0 for name in known_providers}
    full.update(raw)
    floor = min(full.values())
    return {
        name: round(min(value - floor, MAX_PENALTY_MS), 3)
        for name, value in full.items()
    }


def _load_providers(pr: dict[str, Any], cfg: Config, errors: list[str]) -> None:
    if "order" in pr:
        raw_order = pr["order"]
        if isinstance(raw_order, list):
            order = [p for p in (_as_str(v, "providers.order[]", errors) for v in raw_order) if p]
            cfg.providers.order = order
        else:
            errors.append("providers.order: expected a list of provider names — ignored")
    raw_penalties: dict[str, float] = {}
    legacy = False
    if "penalties_ms" in pr:
        raw_penalties = _read_penalties(
            pr["penalties_ms"], "providers.penalties_ms", errors
        )
    elif "weights" in pr:
        raw_penalties = _convert_legacy_weights(pr["weights"], errors)
        legacy = bool(raw_penalties)
    if raw_penalties:
        # Drop unknown names *before* normalising. Anchoring happens at the
        # minimum, so `{ typo = -1000, nordvpn = 0, mullvad = 10 }` would let a
        # misspelling shift every real provider to the cap and erase the 10ms
        # difference the user actually asked for.
        unknown = sorted(set(raw_penalties) - set(KNOWN_PROVIDERS))
        if unknown:
            errors.append(
                "unknown provider(s) in providers.penalties_ms, ignored: "
                + ", ".join(unknown)
            )
            raw_penalties = {
                name: ms for name, ms in raw_penalties.items() if name not in unknown
            }
    if raw_penalties:
        cfg.providers.penalties_ms = normalize_penalties(raw_penalties, KNOWN_PROVIDERS)
        applied = ", ".join(
            f"{name} = {ms:g}" for name, ms in sorted(cfg.providers.penalties_ms.items())
        )
        if legacy:
            errors.append(
                "providers.weights has been replaced by providers.penalties_ms "
                "(milliseconds), because a multiplicative weight meant something "
                f"different on every link. Converted at "
                f"{LEGACY_WEIGHT_REFERENCE_MS:.0f}ms reference to: "
                f"penalties_ms = {{ {applied} }} — copy that into your config."
            )
        elif cfg.providers.penalties_ms != {
            name: round(value, 3) for name, value in raw_penalties.items()
        }:
            errors.append(
                f"providers.penalties_ms normalised to {{ {applied} }} "
                f"(anchored at 0, capped at {MAX_PENALTY_MS:g}ms)"
            )
    if "others_allowed" in pr:
        value = _as_bool(pr["others_allowed"], "providers.others_allowed", errors)
        if value is not None:
            cfg.providers.others_allowed = value
    if "others_threshold_ms" in pr:
        value = _as_float(
            pr["others_threshold_ms"], "providers.others_threshold_ms", errors
        )
        if value is not None:
            cfg.providers.others_threshold_ms = value


def _load_defaults(df: dict[str, Any], cfg: Config, errors: list[str]) -> None:
    if "feature" in df:
        value = _as_str(df["feature"], "defaults.feature", errors)
        if value is not None:
            cfg.defaults.feature = value or None
    for key in ("scope", "probe"):
        if key in df:
            value = _as_str(df[key], f"defaults.{key}", errors)
            if value is not None:
                setattr(cfg.defaults, key, value)
    for key in ("top", "rounds", "count"):
        if key in df:
            value = _as_int(df[key], f"defaults.{key}", errors)
            if value is not None:
                setattr(cfg.defaults, key, value)
    if "timeout" in df:
        value = _as_float(df["timeout"], "defaults.timeout", errors)
        if value is not None:
            cfg.defaults.timeout = value


def _load_geo(g: dict[str, Any], cfg: Config, errors: list[str]) -> None:
    for key in ("lookup", "country", "mmdb_path"):
        if key in g:
            value = _as_str(g[key], f"geo.{key}", errors)
            if value is not None:
                setattr(cfg.geo, key, value or None)
    if "coords" in g:
        raw = g["coords"]
        if isinstance(raw, list) and len(raw) == 2:
            lat = _as_float(raw[0], "geo.coords[0]", errors)
            lon = _as_float(raw[1], "geo.coords[1]", errors)
            if lat is not None and lon is not None:
                cfg.geo.coords = (lat, lon)
        else:
            errors.append("geo.coords: expected [lat, lon] — ignored")


def load_config(path: Path | None = None) -> Config:
    """Read config.toml, coercing values and collecting problems as warnings.

    A malformed value never raises: it is reported on `Config.load_errors` and
    the built-in default is kept, so a typo cannot take down every command.
    """
    p = path or default_config_path()
    cfg = Config()
    if not p.exists():
        return cfg
    errors = cfg.load_errors
    try:
        raw = tomllib.loads(p.read_text())
    except (OSError, tomllib.TOMLDecodeError) as e:
        errors.append(f"could not read {p}: {e} — using defaults")
        return cfg

    if isinstance(pr := raw.get("providers"), dict):
        _load_providers(pr, cfg, errors)
    if isinstance(df := raw.get("defaults"), dict):
        _load_defaults(df, cfg, errors)
    if isinstance(g := raw.get("geo"), dict):
        _load_geo(g, cfg, errors)
    if isinstance(h := raw.get("history"), dict) and "sticky" in h:
        value = _as_bool(h["sticky"], "history.sticky", errors)
        if value is not None:
            cfg.history.sticky = value
    return cfg


DEFAULT_CONFIG_TOML = """\
# Nearest Exit configuration
# https://github.com/faeton/nearest-exit

# Out of the box this file changes nothing: with no preferences set, relays
# are ranked on measurement alone. Uncomment what you actually want.

[providers]
# Providers you pay for, most → least preferred. Relays from these are always
# shown. Leave it unset to rank purely on measurement. Listing *every*
# provider is the same as listing none, and also switches off
# others_threshold_ms below.
# order = ["nordvpn", "airvpn"]

# Milliseconds added to a provider's measured cost before ranking, so a
# less-preferred relay must be that much faster to win. The value is
# absolute: 10ms means 10ms on a fibre link and on a satellite link alike.
# Providers you leave out sit at 0, and the lowest entry is normalised to 0,
# so only the gaps matter. Allowed range: 200ms of spread.
# penalties_ms = { nordvpn = 0.0, airvpn = 5.0, pia = 10.0, mullvad = 15.0 }

# If true, providers missing from `order` are still probed and surfaced
# when they clearly beat the best preferred relay.
others_allowed = true

# A relay from a provider not in `order` must beat the best preferred
# relay's measured cost by this many milliseconds to be recommended.
others_threshold_ms = 5.0

[defaults]
# Which relays qualify at all.
# feature = "wireguard"

# How to measure them, which is a separate question. "auto" is ICMP with a
# TCP-connect fallback. "openvpn" talks to the VPN daemon's control channel
# instead of the IP stack in front of it — a relay can answer ping quickly
# while its OpenVPN process is loaded or routed differently. Not every
# provider publishes an OpenVPN endpoint; Mullvad has none at all.
probe = "auto"     # auto | icmp | tcp | openvpn | socks5

scope = "nearby"   # here | nearby | global
top = 3
# Packets per probe. Below about 5, a single dropped packet is a large
# fraction of the sample and the ranking gets noisy.
count = 5
timeout = 2.0

[history]
# Give a relay that has won on this network before a small head start, so the
# recommendation stops flip-flopping between near-identical relays. Off by
# default: it is a preference for stability, not a measurement, and it makes
# past winners more likely to win again.
sticky = false

[geo]
# How to determine your public location.
#   "ipinfo"  - one HTTPS call to ipinfo.io (default; gets city/country/coords)
#   "stun"    - UDP-only public IP discovery; pair with mmdb_path for offline geo
#   "none"    - no auto-detection; rely on `country` / `coords` overrides below
lookup = "ipinfo"

# Manual override. If set, no lookup is performed.
# country = "YE"
# coords  = [15.5, 48.5]

# Optional MaxMind GeoLite2-City database for offline IP→geo resolution.
# Used together with `lookup = "stun"` for a fully-offline path after the
# database is downloaded once. Get one for free at maxmind.com.
# mmdb_path = "~/.local/share/nearest-exit/GeoLite2-City.mmdb"
"""


def write_default_config(path: Path | None = None) -> Path:
    p = path or default_config_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    if not p.exists():
        p.write_text(DEFAULT_CONFIG_TOML)
    return p
