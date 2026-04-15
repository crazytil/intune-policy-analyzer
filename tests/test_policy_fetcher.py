from __future__ import annotations

import asyncio
import sys
import time
import unittest
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from policy_fetcher import POLICY_ENDPOINTS, _fetch_policy_type
from models import PolicyType


class FakeGraphClient:
    def __init__(self) -> None:
        self.active_requests = 0
        self.max_active_requests = 0
        self.batch_calls = 0

    async def get(self, endpoint: str, params: dict[str, str] | None = None) -> list[dict[str, Any]]:
        self.active_requests += 1
        self.max_active_requests = max(self.max_active_requests, self.active_requests)
        try:
            await asyncio.sleep(0.02)
            if endpoint == POLICY_ENDPOINTS[PolicyType.SETTINGS_CATALOG]["endpoint"]:
                return [
                    {"id": "policy-1", "displayName": "Policy 1"},
                    {"id": "policy-2", "displayName": "Policy 2"},
                    {"id": "policy-3", "displayName": "Policy 3"},
                ]
            if endpoint.endswith("/assignments"):
                return [{"target": {"@odata.type": "#microsoft.graph.groupAssignmentTarget", "groupId": "group-1"}}]
            if endpoint.endswith("/settings"):
                return [{"settingDefinitions": [], "settingInstance": {"settingDefinitionId": "setting-1"}}]
            return []
        finally:
            self.active_requests -= 1

    async def batch_get(
        self,
        endpoints: list[str],
        params_by_endpoint: dict[str, dict[str, str]] | None = None,
    ) -> dict[str, list[dict[str, Any]]]:
        self.batch_calls += 1
        result: dict[str, list[dict[str, Any]]] = {}
        for endpoint in endpoints:
            if endpoint.endswith("/assignments"):
                result[endpoint] = [{"target": {"@odata.type": "#microsoft.graph.groupAssignmentTarget", "groupId": "group-1"}}]
            elif endpoint.endswith("/settings"):
                result[endpoint] = [{"settingDefinitions": [], "settingInstance": {"settingDefinitionId": "setting-1"}}]
            else:
                result[endpoint] = []
        return result


class PolicyFetcherTests(unittest.IsolatedAsyncioTestCase):
    async def test_fetch_policy_type_fetches_policy_details_concurrently(self) -> None:
        client = FakeGraphClient()

        started = time.perf_counter()
        policies = await _fetch_policy_type(client, PolicyType.SETTINGS_CATALOG)
        elapsed = time.perf_counter() - started

        self.assertEqual(len(policies), 3)
        self.assertTrue(client.max_active_requests > 1 or client.batch_calls > 0)
        self.assertLess(elapsed, 0.12)

    async def test_fetch_policy_type_uses_batch_requests_when_available(self) -> None:
        client = FakeGraphClient()

        policies = await _fetch_policy_type(client, PolicyType.SETTINGS_CATALOG)

        self.assertEqual(len(policies), 3)
        self.assertEqual(client.batch_calls, 2)


if __name__ == "__main__":
    unittest.main()
