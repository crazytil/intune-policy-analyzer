from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from typing import Awaitable, Callable, Generic, Optional, TypeVar

K = TypeVar("K")
V = TypeVar("V")


class TTLCache(Generic[K, V]):
    def __init__(self, ttl_seconds: float, max_entries: int = 128) -> None:
        self._ttl_seconds = ttl_seconds
        self._max_entries = max_entries
        self._entries: OrderedDict[K, tuple[float, V]] = OrderedDict()

    def get(self, key: K) -> Optional[V]:
        entry = self._entries.get(key)
        if entry is None:
            return None

        expires_at, value = entry
        if expires_at <= time.monotonic():
            self._entries.pop(key, None)
            return None

        self._entries.move_to_end(key)
        return value

    def set(self, key: K, value: V) -> None:
        self._entries[key] = (time.monotonic() + self._ttl_seconds, value)
        self._entries.move_to_end(key)
        self._evict_expired()
        while len(self._entries) > self._max_entries:
            self._entries.popitem(last=False)

    def pop(self, key: K) -> Optional[V]:
        entry = self._entries.pop(key, None)
        if entry is None:
            return None
        _, value = entry
        return value

    def clear(self) -> None:
        self._entries.clear()

    def _evict_expired(self) -> None:
        now = time.monotonic()
        expired_keys = [
            key for key, (expires_at, _) in self._entries.items() if expires_at <= now
        ]
        for key in expired_keys:
            self._entries.pop(key, None)


class AsyncSingleFlight(Generic[K, V]):
    def __init__(self) -> None:
        self._tasks: dict[K, asyncio.Task[V]] = {}
        self._lock = asyncio.Lock()

    async def run(self, key: K, factory: Callable[[], Awaitable[V]]) -> V:
        async with self._lock:
            task = self._tasks.get(key)
            if task is None:
                task = asyncio.create_task(factory())
                self._tasks[key] = task

        try:
            return await asyncio.shield(task)
        finally:
            async with self._lock:
                current = self._tasks.get(key)
                if current is task and task.done():
                    self._tasks.pop(key, None)
