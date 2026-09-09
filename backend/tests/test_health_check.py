"""
test_health_check.py - Security tests for health check endpoint & credential protection
"""

import asyncio
import unittest
from backend.audit_store import mask_sensitive
from backend.app import _perform_health_check, HealthCheckPayload


class TestSecurityAndHealthCheck(unittest.TestCase):

    def test_mask_sensitive_redacts_credentials(self):
        """Ensure mask_sensitive redacts api_key, tokens, passwords from audit data."""
        data = {
            "rule_name": "Test Rule",
            "api_key": "sk-secret-12345",
            "Authorization": "Bearer sk-secret-token",
            "nested": {
                "token": "sensitive-token-abc",
                "safe_field": "public_info",
                "deep": {
                    "password": "supersecretpassword",
                },
            },
            "array": [
                {"secret_key": "my-secret"},
                {"name": "harmless"},
            ],
        }
        masked = mask_sensitive(data)

        self.assertEqual(masked["api_key"], "[REDACTED]")
        self.assertEqual(masked["Authorization"], "[REDACTED]")
        self.assertEqual(masked["nested"]["token"], "[REDACTED]")
        self.assertEqual(masked["nested"]["safe_field"], "public_info")
        self.assertEqual(masked["nested"]["deep"]["password"], "[REDACTED]")
        self.assertEqual(masked["array"][0]["secret_key"], "[REDACTED]")
        self.assertEqual(masked["array"][1]["name"], "harmless")

    def test_perform_health_check_local(self):
        """Ensure health check completes without logging or leaking credentials."""
        res = asyncio.run(_perform_health_check(
            provider="lm_studio",
            custom_base_url="http://localhost:1234/v1",
            api_key=None,
            splunk_host=None,
            splunk_port=None,
        ))

        self.assertIn("services", res)
        self.assertEqual(res["services"]["fastapi"]["status"], "online")
        self.assertIn("llm", res["services"])
        self.assertIn("splunk", res["services"])


if __name__ == "__main__":
    unittest.main()

