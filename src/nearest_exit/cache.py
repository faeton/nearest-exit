from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any


def default_cache_dir() -> Path:
    xdg = os.environ.get("XDG_CACHE_HOME")
    base = Path(xdg) if xdg else Path.home() / ".cache"
    return base / "nearest-exit"


class JsonCache:
    """On-disk JSON cache that degrades to a miss instead of an exception.

    Writes land in a sibling temp file and are moved into place with
    os.replace(), so a fetch killed mid-write cannot leave a truncated entry
    that later looks fresh. Reads treat anything unparsable as absent, so a
    cache damaged by other means self-heals on the next fetch rather than
    wedging the tool until the user clears it by hand.
    """

    def __init__(
        self,
        cache_dir: Path | None = None,
        ttl_seconds: int = 24 * 3600,
        enabled: bool = True,
    ):
        self.dir = cache_dir or default_cache_dir()
        self.ttl = ttl_seconds
        self.enabled = enabled
        self._memo: dict[Path, tuple[float, Any]] = {}
        # With the disk cache off, entries live here for the process lifetime
        # instead. "Do not persist between runs" is what people mean by
        # --no-cache; refetching the same provider several times inside one run
        # is not, and a single run asks for a provider's set more than once.
        self._ram: dict[str, tuple[float, Any]] = {}

    def _path(self, key: str) -> Path:
        return self.dir / f"{key}.json"

    def _read(self, key: str) -> tuple[bool, Any]:
        """Return (usable, payload); usable is False for missing or corrupt entries.

        Parsed payloads are memoized per (path, mtime) so the fresh()-then-load()
        call pattern does not read and decode a multi-megabyte relay list twice.
        """
        p = self._path(key)
        try:
            mtime = p.stat().st_mtime
        except OSError:
            return False, None
        memo = self._memo.get(p)
        if memo is not None and memo[0] == mtime:
            return True, memo[1]
        try:
            data = json.loads(p.read_text())
        except (OSError, ValueError):
            return False, None
        self._memo[p] = (mtime, data)
        return True, data

    def fresh(self, key: str) -> bool:
        if not self.enabled:
            entry = self._ram.get(key)
            return entry is not None and (time.time() - entry[0]) < self.ttl
        p = self._path(key)
        try:
            age = time.time() - p.stat().st_mtime
        except OSError:
            return False
        if age >= self.ttl:
            return False
        return self._read(key)[0]

    def load(self, key: str) -> Any:
        """Cached payload, or None if the entry is missing or corrupt.

        Ignores the TTL so callers can still fall back to a stale-but-valid
        entry; fresh() is the age check.
        """
        if not self.enabled:
            entry = self._ram.get(key)
            return entry[1] if entry else None
        return self._read(key)[1]

    def save(self, key: str, data: Any) -> None:
        if not self.enabled:
            self._ram[key] = (time.time(), data)
            return
        self.dir.mkdir(parents=True, exist_ok=True)
        dest = self._path(key)
        fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=f".{key}.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(json.dumps(data))
            os.replace(tmp, dest)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
        self._memo.pop(dest, None)
