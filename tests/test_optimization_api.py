from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

import main
from models import Policy, PolicyType


class OptimizationApiTests(unittest.TestCase):
    def test_returns_camel_case_findings_from_cached_policies(self):
        policies = {
            key: Policy(
                id=key, display_name=key, policy_type=PolicyType.DEVICE_CONFIGURATION,
                platform="windows",
                assignments=[{"target": {
                    "@odata.type": "#microsoft.graph.groupAssignmentTarget", "groupId": "pilot",
                }}],
                raw={"edgeBlockPopups": True},
            )
            for key in ("first", "second")
        }
        with patch.object(main, "_ensure_policies_loaded", new_callable=AsyncMock), \
             patch.object(main, "_policies_cache", policies):
            client = TestClient(main.app)
            response = client.get("/api/optimize?platform=Windows&groupId=pilot")
            self.assertEqual(response.status_code, 200)
            body = response.json()
            self.assertEqual(body["summary"]["consolidationCandidates"], 1)
            self.assertEqual(body["findings"][0]["policyCount"], 2)
            self.assertEqual(client.get("/api/optimize?platform=ios").json()["findings"], [])
            self.assertEqual(client.get("/api/optimize?groupId=other").json()["findings"], [])

    def test_returns_authentication_error_when_policy_loading_requires_login(self):
        with patch.object(main, "_ensure_policies_loaded", new_callable=AsyncMock,
                          side_effect=RuntimeError("Not authenticated")):
            self.assertEqual(TestClient(main.app).get("/api/optimize").status_code, 401)
