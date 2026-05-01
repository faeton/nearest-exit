from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any


def default_cache_dir() -> Path:
    xdg = os.environ.get("XDG_CACHE_HOME")
    base = Path(xdg) if xdg else Path.home() / ".cache"
    return base / "nearest-exit"


class JsonCache:
    def __init__(self, cache_dir: Path | None = None, ttl_seconds: int = 24 * 3600):
        self.dir = cache_dir or default_cache_dir()
        self.ttl = ttl_seconds

    def _path(self, key: str) -> Path:
        return self.dir / f"{key}.json"

    def fresh(self, key: str) -> bool:
        p = self._path(key)
        return p.exists() and (time.time() - p.stat().st_mtime) < self.ttl

    def load(self, key: str) -> Any:
        return json.loads(self._path(key).read_text())

    def save(self, key: str, data: Any) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        self._path(key).write_text(json.dumps(data))
