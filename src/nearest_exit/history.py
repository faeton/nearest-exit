from __future__ import annotations

import hashlib
import os
import sqlite3
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    network_fp TEXT NOT NULL,
    provider TEXT NOT NULL,
    relay_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    country_code TEXT,
    rtt_ms REAL,
    loss REAL,
    jitter_ms REAL,
    success INTEGER NOT NULL,
    rank INTEGER
);
CREATE INDEX IF NOT EXISTS idx_scans_fp_ts ON scans(network_fp, ts);
CREATE INDEX IF NOT EXISTS idx_scans_relay ON scans(network_fp, provider, relay_id);
"""


def default_db_path() -> Path:
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "nearest-exit" / "history.sqlite"


def network_fingerprint(asn: str | None) -> str:
    """Stable per-network identifier. Prefers ASN; falls back to default-route
    interface name. Hashed so the DB never stores raw network identifiers."""
    parts: list[str] = []
    if asn:
        parts.append(asn)
    iface = _default_route_iface()
    if iface:
        parts.append(iface)
    if not parts:
        parts.append("unknown")
    h = hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]
    return h


def _default_route_iface() -> str | None:
    try:
        if sys.platform == "darwin":
            out = subprocess.run(
                ["route", "-n", "get", "default"],
                capture_output=True, text=True, timeout=2,
            ).stdout
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("interface:"):
                    return line.split(":", 1)[1].strip() or None
        elif sys.platform.startswith("linux"):
            out = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, timeout=2,
            ).stdout
            parts = out.split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
    except Exception:
        pass
    return None


@contextmanager
def _conn(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(path)
    try:
        c.executescript(SCHEMA)
        yield c
        c.commit()
    finally:
        c.close()


def record_scan(
    rows: list[dict],
    network_fp: str,
    db_path: Path | None = None,
) -> None:
    if not rows:
        return
    p = db_path or default_db_path()
    ts = int(time.time())
    with _conn(p) as c:
        c.executemany(
            """INSERT INTO scans
               (ts, network_fp, provider, relay_id, hostname, country_code,
                rtt_ms, loss, jitter_ms, success, rank)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            [
                (
                    ts, network_fp, r["provider"], r["relay_id"], r["hostname"],
                    r.get("country_code"), r.get("rtt_ms"), r.get("loss"),
                    r.get("jitter_ms"), 1 if r["success"] else 0, r.get("rank"),
                )
                for r in rows
            ],
        )


def recent_winners(
    network_fp: str,
    since_seconds: int = 7 * 24 * 3600,
    db_path: Path | None = None,
) -> dict[tuple[str, str], int]:
    """Map (provider, relay_id) → count of times this relay ranked #1 within window."""
    p = db_path or default_db_path()
    if not p.exists():
        return {}
    cutoff = int(time.time()) - since_seconds
    with _conn(p) as c:
        cur = c.execute(
            """SELECT provider, relay_id, COUNT(*) FROM scans
               WHERE network_fp=? AND ts>=? AND rank=1
               GROUP BY provider, relay_id""",
            (network_fp, cutoff),
        )
        return {(r[0], r[1]): r[2] for r in cur.fetchall()}


STICKY_RTT_BONUS_MS = 3.0


def sticky_bonus(provider: str, relay_id: str,
                 winners: dict[tuple[str, str], int]) -> float:
    """Return ms to subtract from a relay's effective RTT for ranking only.
    Anti-flap: previous-winner gets a small head start, capped."""
    n = winners.get((provider, relay_id), 0)
    if n <= 0:
        return 0.0
    return min(STICKY_RTT_BONUS_MS * n, 8.0)
