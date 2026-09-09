"""
test_llm_client.py - Unit tests for dynamic API key handling and dual-model routing
"""

import os
import unittest
from backend.llm_client import (
    OpenAICompatibleClient,
    get_llm_client,
    LLMAuthError,
)


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


if __name__ == "__main__":
    unittest.main()

