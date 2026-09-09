"""
test_splunk_client.py - Unit tests for Splunk REST client configuration & validation
"""

import os
import unittest
from unittest.mock import patch, MagicMock
from backend.splunk_client import SplunkTestClient


class TestSplunkClient(unittest.TestCase):

    def test_init_from_env_vars(self):
        """Verify client correctly reads SPLUNK_HOST, SPLUNK_USER, and SPLUNK_PASSWORD from environment."""
        with patch.dict(os.environ, {
            "SPLUNK_HOST": "https://splunk:8089",
            "SPLUNK_USER": "admin",
            "SPLUNK_PASSWORD": "ChangeMe123!",
        }):
            client = SplunkTestClient()
            self.assertEqual(client.base_url, "https://splunk:8089")
            self.assertEqual(client.host, "splunk")
            self.assertEqual(client.port, 8089)
            self.assertEqual(client.username, "admin")
            self.assertEqual(client.password, "ChangeMe123!")
            self.assertFalse(client.verify_ssl)

    def test_init_with_bare_hostname(self):
        """Verify client constructs base_url from bare hostname and port."""
        with patch.dict(os.environ, {
            "SPLUNK_HOST": "splunk",
            "SPLUNK_PORT": "8089",
            "SPLUNK_USER": "admin",
            "SPLUNK_PASSWORD": "ChangeMe123!",
        }):
            client = SplunkTestClient()
            self.assertEqual(client.base_url, "https://splunk:8089")
            self.assertEqual(client.username, "admin")
            self.assertEqual(client.password, "ChangeMe123!")
            self.assertFalse(client.verify_ssl)

    def test_parse_splunk_error_json(self):
        """Verify extraction of error messages from Splunk JSON error payload."""
        json_error = '{"messages":[{"type":"FATAL","text":"Error in \'eval\' command: Type mismatch"}]}'
        parsed = SplunkTestClient._parse_splunk_error(json_error, 400)
        self.assertIn("Type mismatch", parsed)

    def test_parse_splunk_error_xml(self):
        """Verify extraction of error messages from Splunk XML error payload."""
        xml_error = '<response><messages><msg type="FATAL">Search syntax error at index 14</msg></messages></response>'
        parsed = SplunkTestClient._parse_splunk_error(xml_error, 400)
        self.assertEqual(parsed, "Search syntax error at index 14")

    def test_auth_tuple(self):
        """Verify HTTP Basic Auth tuple generated correctly."""
        client = SplunkTestClient(
            host="https://splunk:8089",
            username="admin",
            password="ChangeMe123!",
        )
        self.assertEqual(client._get_auth(), ("admin", "ChangeMe123!"))


if __name__ == "__main__":
    unittest.main()

