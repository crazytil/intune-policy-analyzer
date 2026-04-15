from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from graph_client import GraphClient


class FakeResponse:
    def __init__(self, payload: dict[str, object], status_code: int = 200) -> None:
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self) -> dict[str, object]:
        return self._payload


class GraphClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_batch_get_follows_next_link_pages(self) -> None:
        client = GraphClient()
        client._request_with_retry = AsyncMock(
            side_effect=[
                FakeResponse(
                    {
                        "responses": [
                            {
                                "id": "1",
                                "status": 200,
                                "body": {
                                    "value": [{"id": "page-1"}],
                                    "@odata.nextLink": "https://graph.microsoft.com/beta/next-page",
                                },
                            }
                        ]
                    }
                ),
                FakeResponse({"value": [{"id": "page-2"}]}),
            ]
        )

        result = await client.batch_get(["deviceManagement/configurationPolicies/policy-1/settings"])

        self.assertEqual(
            result["deviceManagement/configurationPolicies/policy-1/settings"],
            [{"id": "page-1"}, {"id": "page-2"}],
        )
        self.assertEqual(client._request_with_retry.await_count, 2)


if __name__ == "__main__":
    unittest.main()
