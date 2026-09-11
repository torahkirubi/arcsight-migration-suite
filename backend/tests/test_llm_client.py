"""
test_llm_client.py - Unit tests for dynamic API key handling and dual-model routing
"""

import os
import unittest
from backend.llm_client import (
    OpenAICompatibleClient,
    get_llm_client,
    LLMAuthError,
    LLMError,
)
from unittest.mock import patch, MagicMock, AsyncMock


class TestLLMClientAuth(unittest.TestCase):

    def test_dynamic_api_key_passed_from_request(self):
        """Ensure client uses the dynamic api_key passed from frontend request."""
        client = get_llm_client(
            provider="cloud_openai",
            api_key="sk-test-dynamic-key-12345",
            model_name="gpt-4o",
        )
        self.assertEqual(client.api_key, "sk-test-dynamic-key-12345")
        self.assertEqual(client.provider_name, "Cloud OpenAI")

    def test_custom_provider_preserves_endpoint_and_model(self):
        """Unknown provider names use the supplied OpenAI-compatible route."""
        client = get_llm_client(
            provider="claude",
            custom_base_url="https://api.anthropic.com/v1",
            api_key="sk-ant-test",
            model_name="claude-sonnet-4",
        )
        self.assertEqual(client.provider_name, "claude")
        self.assertEqual(client.base_url, "https://api.anthropic.com/v1")
        self.assertEqual(client.default_model, "claude-sonnet-4")
        self.assertEqual(client.api_key, "sk-ant-test")

    def test_bearer_prefix_cleaned(self):
        """Ensure 'Bearer ' prefix is stripped if user pastes it."""
        client = get_llm_client(
            provider="cloud_openai",
            api_key="Bearer sk-user-pasted-bearer",
        )
        self.assertEqual(client.api_key, "sk-user-pasted-bearer")

    def test_lm_studio_default_key(self):
        """Ensure LM Studio local uses 'lm-studio' or provided key."""
        client = get_llm_client(provider="lm_studio")
        self.assertEqual(client.api_key, "lm-studio")

    def test_cloud_openai_without_key_raises_auth_error_on_complete(self):
        """Ensure missing API key for cloud provider raises LLMAuthError without sending invalid requests."""
        # Ensure env is empty for test
        old_env = os.environ.get("OPENAI_API_KEY")
        if "OPENAI_API_KEY" in os.environ:
            del os.environ["OPENAI_API_KEY"]

        try:
            client = get_llm_client(provider="cloud_openai", api_key="")
            self.assertEqual(client.api_key, "")

            import asyncio
            with self.assertRaises(LLMAuthError) as ctx:
                asyncio.run(client.complete(prompt="test"))
            self.assertIn("No API key provided", str(ctx.exception))
        finally:
            if old_env:
                os.environ["OPENAI_API_KEY"] = old_env

    def test_health_check_reports_unauthorized_gracefully_when_key_missing(self):
        """Ensure health check reports status='unauthorized' if key is missing instead of making doomed call."""
        old_env = os.environ.get("OPENAI_API_KEY")
        if "OPENAI_API_KEY" in os.environ:
            del os.environ["OPENAI_API_KEY"]

        try:
            client = get_llm_client(provider="cloud_openai", api_key="")
            import asyncio
            res = asyncio.run(client.health_check())
            self.assertEqual(res["status"], "unauthorized")
            self.assertIn("API key required", res["error"])
        finally:
            if old_env:
                os.environ["OPENAI_API_KEY"] = old_env

    def test_gemini_provider_missing_key_raises_llm_error(self):
        """Assert that Gemini provider without API key raises LLMError before making request."""
        old_env = os.environ.get("GEMINI_API_KEY")
        if "GEMINI_API_KEY" in os.environ:
            del os.environ["GEMINI_API_KEY"]

        try:
            client = get_llm_client(provider="gemini", api_key="")
            import asyncio
            with self.assertRaises(LLMError) as ctx:
                asyncio.run(client.complete(prompt="test"))
            self.assertIn("Gemini API key is not configured in vault or environment", str(ctx.exception))
        finally:
            if old_env:
                os.environ["GEMINI_API_KEY"] = old_env

    def test_gemini_provider_query_param_and_bearer(self):
        """Assert that Gemini provider includes ?key=<api_key> on endpoint and Authorization header."""
        from backend.llm_client import HAS_HTTPX
        import json
        client = get_llm_client(provider="gemini", api_key="AIzaSy-sample-key-12345")
        self.assertEqual(client.provider_name, "Google Gemini")
        self.assertEqual(client.api_key, "AIzaSy-sample-key-12345")

        import asyncio

        if HAS_HTTPX:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "choices": [{"message": {"content": "mock response"}, "finish_reason": "stop"}]
            }

            with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
                mock_post.return_value = mock_resp
                res = asyncio.run(client.complete(prompt="hello"))
                self.assertEqual(res, "mock response")

                call_args, call_kwargs = mock_post.call_args
                called_url = call_args[0]
                called_headers = call_kwargs.get("headers", {})

                # Assert ?key= is appended
                self.assertIn("key=AIzaSy-sample-key-12345", called_url)
                # Assert Authorization: Bearer is present
                self.assertEqual(called_headers.get("Authorization"), "Bearer AIzaSy-sample-key-12345")
                # Assert x-goog-api-key is present
                self.assertEqual(called_headers.get("x-goog-api-key"), "AIzaSy-sample-key-12345")
        else:
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps({
                "choices": [{"message": {"content": "mock response"}, "finish_reason": "stop"}]
            }).encode("utf-8")
            mock_resp.__enter__.return_value = mock_resp

            with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
                res = asyncio.run(client.complete(prompt="hello"))
                self.assertEqual(res, "mock response")

                req = mock_urlopen.call_args[0][0]
                self.assertIn("key=AIzaSy-sample-key-12345", req.full_url)
                self.assertEqual(req.get_header("Authorization"), "Bearer AIzaSy-sample-key-12345")
                self.assertEqual(req.get_header("X-goog-api-key"), "AIzaSy-sample-key-12345")

    def test_default_max_tokens_and_completion_tokens_in_payload(self):
        """Ensure complete() defaults to max_tokens=8192 and only sends max_tokens without max_completion_tokens."""
        from backend.llm_client import HAS_HTTPX
        import json
        import asyncio

        client = get_llm_client(provider="lm_studio")
        if HAS_HTTPX:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]
            }
            with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
                mock_post.return_value = mock_resp
                asyncio.run(client.complete(prompt="hello"))
                payload = mock_post.call_args[1]["json"]
                self.assertEqual(payload.get("max_tokens"), 8192)
                self.assertNotIn("max_completion_tokens", payload)
        else:
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps({
                "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]
            }).encode("utf-8")
            mock_resp.__enter__.return_value = mock_resp
            with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
                asyncio.run(client.complete(prompt="hello"))
                req = mock_urlopen.call_args[0][0]
                payload = json.loads(req.data.decode("utf-8"))
                self.assertEqual(payload.get("max_tokens"), 8192)
                self.assertNotIn("max_completion_tokens", payload)

    def test_finish_reason_length_returns_accumulated_content(self):
        """Ensure finish_reason='length' returns accumulated content without error if content is non-empty."""
        from backend.llm_client import HAS_HTTPX
        import json
        import asyncio

        client = get_llm_client(provider="lm_studio")
        if HAS_HTTPX:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "choices": [{"message": {"content": '{"noise_source": "scanner"}'}, "finish_reason": "length"}]
            }
            with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
                mock_post.return_value = mock_resp
                res = asyncio.run(client.complete(prompt="hello"))
                self.assertEqual(res, '{"noise_source": "scanner"}')
        else:
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps({
                "choices": [{"message": {"content": '{"noise_source": "scanner"}'}, "finish_reason": "length"}]
            }).encode("utf-8")
            mock_resp.__enter__.return_value = mock_resp
            with patch("urllib.request.urlopen", return_value=mock_resp):
                res = asyncio.run(client.complete(prompt="hello"))
                self.assertEqual(res, '{"noise_source": "scanner"}')

    def test_finish_reason_length_raises_when_content_empty(self):
        """Ensure finish_reason='length' raises LLMTruncationError if content is empty."""
        from backend.llm_client import HAS_HTTPX, LLMTruncationError
        import json
        import asyncio

        client = get_llm_client(provider="lm_studio")
        if HAS_HTTPX:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "choices": [{"message": {"content": "   "}, "finish_reason": "length"}]
            }
            with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
                mock_post.return_value = mock_resp
                with self.assertRaises(LLMTruncationError):
                    asyncio.run(client.complete(prompt="hello"))
        else:
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps({
                "choices": [{"message": {"content": "   "}, "finish_reason": "length"}]
            }).encode("utf-8")
            mock_resp.__enter__.return_value = mock_resp
            with patch("urllib.request.urlopen", return_value=mock_resp):
                with self.assertRaises(LLMTruncationError):
                    asyncio.run(client.complete(prompt="hello"))


if __name__ == "__main__":
    unittest.main()

