from __future__ import annotations

import asyncio
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from cache_utils import AsyncSingleFlight, TTLCache


class TTLCacheTests(unittest.TestCase):
    def test_returns_cached_value_before_expiry(self) -> None:
        cache = TTLCache[str, str](ttl_seconds=1, max_entries=2)

        cache.set("alpha", "one")

        self.assertEqual(cache.get("alpha"), "one")

    def test_expires_values_after_ttl(self) -> None:
        cache = TTLCache[str, str](ttl_seconds=0.01, max_entries=2)

        cache.set("alpha", "one")
        time.sleep(0.03)

        self.assertIsNone(cache.get("alpha"))

    def test_evicts_oldest_entry_when_full(self) -> None:
        cache = TTLCache[str, str](ttl_seconds=60, max_entries=2)

        cache.set("alpha", "one")
        cache.set("beta", "two")
        cache.set("gamma", "three")

        self.assertIsNone(cache.get("alpha"))
        self.assertEqual(cache.get("beta"), "two")
        self.assertEqual(cache.get("gamma"), "three")


class AsyncSingleFlightTests(unittest.IsolatedAsyncioTestCase):
    async def test_runs_shared_work_once_per_key(self) -> None:
        singleflight: AsyncSingleFlight[str, int] = AsyncSingleFlight()
        calls = 0

        async def load() -> int:
            nonlocal calls
            calls += 1
            await asyncio.sleep(0.01)
            return 42

        results = await asyncio.gather(
            singleflight.run("policies", load),
            singleflight.run("policies", load),
            singleflight.run("policies", load),
        )

        self.assertEqual(results, [42, 42, 42])
        self.assertEqual(calls, 1)


if __name__ == "__main__":
    unittest.main()
