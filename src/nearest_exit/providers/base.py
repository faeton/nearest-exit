from __future__ import annotations

from typing import Protocol

from ..cache import JsonCache
from ..models import Relay


class ProviderAdapter(Protocol):
    name: str

    async def fetch_relays(self, cache: JsonCache, refresh: bool = False) -> list[Relay]:
        ...
