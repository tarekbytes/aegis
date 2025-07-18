import asyncio
import time
from typing import Any, Optional


class CacheEntry:
    def __init__(self, status: str, data: Any = None, expiry_timestamp: Optional[float] = None):
        self.status = status  # 'fetching' or 'ready'
        self.data = data
        self.expiry_timestamp = expiry_timestamp

class InMemoryAsyncCache:
    def __init__(self):
        self._store = {}
        self._lock = asyncio.Lock()

    async def add_if_not_exists(self, key: str, entry: CacheEntry) -> bool:
        async with self._lock:
            if key in self._store:
                return False
            self._store[key] = entry
            return True

    async def get(self, key: str) -> Optional[CacheEntry]:
        async with self._lock:
            return self._store.get(key)

    async def set(self, key: str, entry: CacheEntry):
        async with self._lock:
            self._store[key] = entry

    async def pop(self, key: str, default: Any = None) -> Optional[CacheEntry]:
        async with self._lock:
            return self._store.pop(key, default)

    async def wait_for_ready(self, key: str, timeout: float = 5.0, poll_interval: float = 0.1) -> Optional[Any]:
        start = time.monotonic()
        while time.monotonic() - start < timeout:
            entry = await self.get(key)
            if entry and entry.status == "ready":
                return entry.data
            await asyncio.sleep(poll_interval)
        return None

cache = InMemoryAsyncCache()
