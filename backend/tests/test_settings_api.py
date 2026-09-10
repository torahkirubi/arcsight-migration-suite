"""
test_settings_api.py - TDD unit tests for Sentinel Settings & Credential API endpoints
"""

import unittest
from unittest.mock import patch, MagicMock
from backend.app import app
from backend.sentinel_client import SentinelClient

try:
    from fastapi.testclient import TestClient
except ImportError:
    class TestResponse:
        """Fallback TestResponse when fastapi is not installed in the test environment."""

        def __init__(self, status_code: int, data: dict):
            self.status_code = status_code
            self._data = data

        def json(self):
            return self._data

    class TestClient:
        """Fallback TestClient when fastapi.testclient is not installed in the test environment."""

        def __init__(self, app=None):
            self.app = app

        def post(self, url: str, json: dict = None, headers: dict = None):
            if self.app is None:
                return TestResponse(404, {"detail": "Endpoint not found (app is None)"})

            routes = getattr(self.app, "routes", [])
            for route in routes:
                route_path = getattr(route, "path", None)
                route_methods = getattr(route, "methods", set())
                if route_path == url and "POST" in route_methods:
                    endpoint = getattr(route, "endpoint", None)
                    if endpoint:
                        import inspect
                        import asyncio

                        sig = inspect.signature(endpoint)
                        kwargs = {}
                        if "payload" in sig.parameters:
                            param = sig.parameters["payload"]
                            ann = param.annotation
                            if ann != inspect.Parameter.empty and callable(ann):
                                try:
                                    kwargs["payload"] = ann(**(json or {}))
                                except Exception:
                                    kwargs["payload"] = json
                            else:
                                kwargs["payload"] = json
                        try:
                            if inspect.iscoroutinefunction(endpoint):
                                res = asyncio.run(endpoint(**kwargs))
                            else:
                                res = endpoint(**kwargs)
                            return TestResponse(200, res if isinstance(res, dict) else {})
                        except Exception as exc:
                            status_code = getattr(exc, "status_code", 500)
                            detail = getattr(exc, "detail", str(exc))
                            return TestResponse(status_code, {"detail": detail, "error": str(exc)})

            router = getattr(self.app, "router", None)
            if router and hasattr(router, "routes"):
                for route in router.routes:
                    if getattr(route, "path", None) == url and "POST" in getattr(route, "methods", set()):
                        endpoint = getattr(route, "endpoint", None)
                        if endpoint:
                            import inspect
                            import asyncio

                            sig = inspect.signature(endpoint)
                            kwargs = {}
                            if "payload" in sig.parameters:
                                param = sig.parameters["payload"]
                                ann = param.annotation
                                if ann != inspect.Parameter.empty and callable(ann):
                                    try:
                                        kwargs["payload"] = ann(**(json or {}))
                                    except Exception:
                                        kwargs["payload"] = json
                                else:
                                    kwargs["payload"] = json
                            try:
                                if inspect.iscoroutinefunction(endpoint):
                                    res = asyncio.run(endpoint(**kwargs))
                                else:
                                    res = endpoint(**kwargs)
                                return TestResponse(200, res if isinstance(res, dict) else {})
                            except Exception as exc:
                                status_code = getattr(exc, "status_code", 500)
                                detail = getattr(exc, "detail", str(exc))
                                return TestResponse(status_code, {"detail": detail, "error": str(exc)})

            return TestResponse(404, {"detail": f"Route {url} not found"})


class TestSettingsApi(unittest.TestCase):
    """Test suite for Sentinel Settings API endpoints."""

    def setUp(self):
        self.valid_payload = {
            "tenant_id": "00000000-0000-0000-0000-000000000001",
            "client_id": "00000000-0000-0000-0000-000000000002",
            "client_secret": "mock-azure-client-secret-xyz",
            "workspace_id": "00000000-0000-0000-0000-000000000003",
        }

    def test_save_sentinel_credentials_success(self):
        """Verify POST /api/settings/sentinel accepts credentials and returns 200 OK success confirmation."""
        client = TestClient(app)
        response = client.post("/api/settings/sentinel", json=self.valid_payload)

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data.get("success", False))

    @patch.object(SentinelClient, "authenticate", return_value="mock-bearer-token-12345")
    def test_sentinel_connection_test_success(self, mock_auth):
        """Verify POST /api/settings/sentinel/test calls authenticate() and returns boolean success=True."""
        client = TestClient(app)
        response = client.post("/api/settings/sentinel/test", json=self.valid_payload)

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data.get("success", False))
        mock_auth.assert_called_once()

    @patch.object(SentinelClient, "authenticate", return_value="")
    def test_sentinel_connection_test_failure(self, mock_auth):
        """Verify POST /api/settings/sentinel/test returns success=False when authenticate() fails."""
        client = TestClient(app)
        response = client.post("/api/settings/sentinel/test", json=self.valid_payload)

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertFalse(data.get("success", True))
        mock_auth.assert_called_once()

    @patch.object(SentinelClient, "authenticate", side_effect=Exception("Azure AAD STS endpoint unreachable"))
    def test_sentinel_connection_test_exception(self, mock_auth):
        """Verify POST /api/settings/sentinel/test returns success=False and error details on connection exception."""
        client = TestClient(app)
        response = client.post("/api/settings/sentinel/test", json=self.valid_payload)

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertFalse(data.get("success", True))
        self.assertIn("Azure AAD STS endpoint unreachable", str(data.get("error", "")) or str(data.get("message", "")))
        mock_auth.assert_called_once()

    def test_save_llm_settings_gemini(self):
        """Verify POST /api/settings/llm saves Gemini API key to vault and updates os.environ."""
        from backend.auth_vault import VaultService
        import os

        client = TestClient(app)
        payload = {
            "provider": "gemini",
            "api_key": "AIzaSy-test-dynamic-gemini-key-12345",
            "model_name": "gemini-1.5-flash",
        }
        response = client.post("/api/settings/llm", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data.get("success", False))
        self.assertIn("gemini key secured in vault", data.get("message", ""))

        # Verify environment variable was set
        self.assertEqual(os.environ.get("GEMINI_API_KEY"), "AIzaSy-test-dynamic-gemini-key-12345")

        # Verify vault persistence
        vault = VaultService()
        self.assertEqual(vault.get_secret("gemini"), "AIzaSy-test-dynamic-gemini-key-12345")

    def test_save_llm_settings_openai(self):
        """Verify POST /api/settings/llm saves OpenAI API key to vault and updates os.environ."""
        from backend.auth_vault import VaultService
        import os

        client = TestClient(app)
        payload = {
            "provider": "cloud_openai",
            "api_key": "sk-test-dynamic-openai-key-99999",
            "model_name": "gpt-4o",
        }
        response = client.post("/api/settings/llm", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data.get("success", False))
        self.assertIn("cloud_openai key secured in vault", data.get("message", ""))

        # Verify environment variable was set
        self.assertEqual(os.environ.get("OPENAI_API_KEY"), "sk-test-dynamic-openai-key-99999")

        # Verify vault persistence
        vault = VaultService()
        self.assertEqual(vault.get_secret("cloud_openai"), "sk-test-dynamic-openai-key-99999")

    def test_save_llm_settings_empty_key_rejected(self):
        """Verify POST /api/settings/llm rejects empty API key."""
        client = TestClient(app)
        payload = {
            "provider": "gemini",
            "api_key": "   ",
        }
        response = client.post("/api/settings/llm", json=payload)
        self.assertIn(response.status_code, (400, 422))


if __name__ == "__main__":
    unittest.main()

