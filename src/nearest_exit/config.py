from __future__ import annotations

import math
import os
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def default_config_path() -> Path:
    if env := os.environ.get("NEAREST_EXIT_CONFIG"):
        return Path(env)
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "nearest-exit" / "config.toml"


@dataclass
class ProvidersConfig:
    order: list[str] = field(default_factory=lambda: ["nordvpn", "airvpn", "mullvad", "pia"])
    weights: dict[str, float] = field(
        default_factory=lambda: {"nordvpn": 1.0, "airvpn": 0.9, "mullvad": 0.7, "pia": 0.8}
    )
    others_allowed: bool = True
    others_threshold_ms: float = 5.0  # non-preferred must beat preferred by this many ms


@dataclass
class DefaultsConfig:
    feature: str | None = None  # e.g. "wireguard"
    scope: str = "here"          # here | nearby | global
    top: int = 3
    rounds: int = 1
    count: int = 3
    timeout: float = 2.0


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
    # Problems found while reading the file. Kept on the object so a bad config
    # surfaces as a warning at the top of a run instead of a traceback.
    load_errors: list[str] = field(default_factory=list)


# Provider weights are a preference dial, not an override. Allowing arbitrarily
# large values lets one provider win regardless of measurement, which defeats
# the point of measuring; clamp to a range where the dial still has to argue.
MIN_WEIGHT = 0.1
MAX_WEIGHT = 10.0


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

    unknown_weights = [p for p in cfg.providers.weights if p not in providers]
    if unknown_weights:
        warnings.append(
            "unknown provider weight(s): "
            + ", ".join(sorted(set(unknown_weights)))
        )

    for provider, weight in cfg.providers.weights.items():
        if not isinstance(weight, int | float) or isinstance(weight, bool):
            warnings.append(f"provider weight for {provider} must be a number")
        elif not math.isfinite(weight) or weight <= 0:
            warnings.append(f"provider weight for {provider} must be a positive number")

    if cfg.providers.others_threshold_ms < 0:
        warnings.append("providers.others_threshold_ms must be >= 0")

    if cfg.defaults.scope not in {"here", "nearby", "global"}:
        warnings.append("defaults.scope must be one of: here, nearby, global")

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


def _load_providers(pr: dict[str, Any], cfg: Config, errors: list[str]) -> None:
    if "order" in pr:
        raw_order = pr["order"]
        if isinstance(raw_order, list):
            order = [p for p in (_as_str(v, "providers.order[]", errors) for v in raw_order) if p]
            cfg.providers.order = order
        else:
            errors.append("providers.order: expected a list of provider names — ignored")
    if "weights" in pr:
        raw_weights = pr["weights"]
        if isinstance(raw_weights, dict):
            weights: dict[str, float] = {}
            for name, value in raw_weights.items():
                w = _as_float(value, f"providers.weights.{name}", errors)
                if w is None:
                    continue
                if w <= 0:
                    errors.append(
                        f"providers.weights.{name}: must be > 0, got {w} — ignored"
                    )
                    continue
                clamped = min(max(w, MIN_WEIGHT), MAX_WEIGHT)
                if clamped != w:
                    errors.append(
                        f"providers.weights.{name}: {w} clamped to {clamped} "
                        f"(allowed range {MIN_WEIGHT}–{MAX_WEIGHT})"
                    )
                weights[name] = clamped
            cfg.providers.weights = weights
        else:
            errors.append("providers.weights: expected a table — ignored")
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
    if "scope" in df:
        value = _as_str(df["scope"], "defaults.scope", errors)
        if value is not None:
            cfg.defaults.scope = value
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
    return cfg


DEFAULT_CONFIG_TOML = """\
# Nearest Exit configuration
# https://github.com/faeton/nearest-exit

[providers]
# Provider preference order, most → least preferred.
order = ["nordvpn", "airvpn", "mullvad", "pia"]

# Per-provider score weight (1.0 = neutral). Lower weight makes a relay
# need to be that much faster to outrank a preferred provider.
# Allowed range: 0.1–10.0.
weights = { nordvpn = 1.0, airvpn = 0.9, mullvad = 0.7, pia = 0.8 }

# If true, non-preferred providers are still probed and surfaced when
# they clearly beat the best preferred relay.
others_allowed = true

# A non-preferred relay must beat the best preferred relay by this many
# milliseconds (median RTT) before being recommended.
others_threshold_ms = 5.0

[defaults]
# feature = "wireguard"
scope = "here"   # here | nearby | global
top = 3
count = 3
timeout = 2.0

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
