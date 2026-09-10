from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))


class StandaloneTests(unittest.TestCase):
    def test_serves_frontend_without_shadowing_api_or_exposing_files(self):
        from standalone import create_app

        with tempfile.TemporaryDirectory() as directory:
            web = Path(directory) / "web"
            web.mkdir()
            (web / "index.html").write_text("<html>Standalone UI</html>")
            (web / "assets").mkdir()
            (web / "assets" / "app.js").write_text("console.log('bundled');")
            (Path(directory) / "secret.txt").write_text("private")
            client = TestClient(create_app(web))
            self.assertEqual(client.get("/").text, "<html>Standalone UI</html>")
            self.assertEqual(client.get("/assets/app.js").text, "console.log('bundled');")
            self.assertEqual(client.get("/api/analyze-conflicts/target/invalid").status_code, 400)
            self.assertEqual(client.get("/api/unknown").status_code, 404)
            self.assertEqual(client.get("/assets/missing.js").status_code, 404)
            self.assertEqual(client.get("/%2e%2e/secret.txt").status_code, 404)

    def test_missing_frontend_fails_with_build_instruction(self):
        from standalone import create_app

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError, "npm run build"):
                create_app(Path(directory))

    def test_cache_defaults_to_user_directory_and_preserves_override(self):
        from standalone import configure_token_cache

        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {"LOCALAPPDATA": directory}, clear=True), \
                 patch("standalone.Path.home", side_effect=RuntimeError("Could not determine home directory.")):
                configure_token_cache()
                expected = Path(directory) / "IntunePolicyAnalyzer" / ".token_cache.json"
                self.assertEqual(os.environ["INTUNE_TOKEN_CACHE_FILE"], str(expected))
                self.assertTrue(expected.parent.is_dir())
            with patch.dict(os.environ, {"INTUNE_TOKEN_CACHE_FILE": "custom.json"}, clear=True):
                configure_token_cache()
                self.assertEqual(os.environ["INTUNE_TOKEN_CACHE_FILE"], "custom.json")


if __name__ == "__main__":
    unittest.main()
