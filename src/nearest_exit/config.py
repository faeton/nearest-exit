from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


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


def load_config(path: Path | None = None) -> Config:
    p = path or default_config_path()
    if not p.exists():
        return Config()
    raw = tomllib.loads(p.read_text())
    cfg = Config()
    if pr := raw.get("providers"):
        if "order" in pr:
            cfg.providers.order = list(pr["order"])
        if "weights" in pr:
            cfg.providers.weights = dict(pr["weights"])
        if "others_allowed" in pr:
            cfg.providers.others_allowed = bool(pr["others_allowed"])
        if "others_threshold_ms" in pr:
            cfg.providers.others_threshold_ms = float(pr["others_threshold_ms"])
    if df := raw.get("defaults"):
        for k in ("feature", "scope", "top", "rounds", "count", "timeout"):
            if k in df:
                setattr(cfg.defaults, k, df[k])
    if g := raw.get("geo"):
        if "lookup" in g:
            cfg.geo.lookup = g["lookup"]
        if "country" in g:
            cfg.geo.country = g["country"]
        if "coords" in g and isinstance(g["coords"], list) and len(g["coords"]) == 2:
            cfg.geo.coords = (float(g["coords"][0]), float(g["coords"][1]))
        if "mmdb_path" in g:
            cfg.geo.mmdb_path = g["mmdb_path"]
    return cfg


DEFAULT_CONFIG_TOML = """\
# Nearest Exit configuration
# https://github.com/faeton/nearest-exit

[providers]
# Provider preference order, most → least preferred.
order = ["nordvpn", "airvpn", "mullvad", "pia"]

# Per-provider score weight (1.0 = neutral). Lower weight makes a relay
# need to be that much faster to outrank a preferred provider.
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
