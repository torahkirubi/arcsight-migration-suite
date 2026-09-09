"""
test_sentinel_client.py - Unit tests for Microsoft Sentinel API client & schema resolver
"""

import os
import unittest
from unittest.mock import patch, MagicMock
from backend.sentinel_client import SentinelClient


class TestSentinelClient(unittest.TestCase):

    def setUp(self):
        self.tenant_id = "mock-tenant-id"
        self.client_id = "mock-client-id"
        self.client_secret = "mock-client-secret"
        self.workspace_id = "mock-workspace-id"

    # Requirement 1: Authentication
    # Mock a standard Azure credential flow to ensure the client initializes properly without hanging.
    @patch("backend.sentinel_client.SentinelClient._acquire_token")
    def test_auth_azure_credential_flow(self, mock_acquire_token):
        mock_acquire_token.return_value = "mock-bearer-token-xyz"
        client = SentinelClient(
            tenant_id=self.tenant_id,
            client_id=self.client_id,
            client_secret=self.client_secret,
            workspace_id=self.workspace_id,
        )
        token = client.authenticate()
        self.assertEqual(token, "mock-bearer-token-xyz")
        self.assertTrue(client.is_authenticated)
        mock_acquire_token.assert_called_once()

    @patch("backend.sentinel_client.SentinelClient._acquire_token")
    def test_init_from_env_vars(self, mock_acquire_token):
        mock_acquire_token.return_value = "mock-token-from-env"
        with patch.dict(os.environ, {
            "AZURE_TENANT_ID": "env-tenant",
            "AZURE_CLIENT_ID": "env-client",
            "AZURE_CLIENT_SECRET": "env-secret",
            "SENTINEL_WORKSPACE_ID": "env-workspace",
        }):
            client = SentinelClient()
            self.assertEqual(client.tenant_id, "env-tenant")
            self.assertEqual(client.client_id, "env-client")
            self.assertEqual(client.workspace_id, "env-workspace")

    # Requirement 2: Schema Fetching
    # Test that the client can query a mock Sentinel workspace and return a list of active tables (e.g., ASimProcessEventLogs, DeviceNetworkEvents).
    @patch("backend.sentinel_client.SentinelClient._execute_query")
    def test_fetch_active_tables(self, mock_execute_query):
        mock_execute_query.return_value = [
            {"TableName": "ASimProcessEventLogs"},
            {"TableName": "DeviceNetworkEvents"},
            {"TableName": "SecurityEvent"},
            {"TableName": "CommonSecurityLog"},
        ]
        client = SentinelClient(
            tenant_id=self.tenant_id,
            client_id=self.client_id,
            client_secret=self.client_secret,
            workspace_id=self.workspace_id,
        )
        tables = client.get_active_tables()
        self.assertIn("ASimProcessEventLogs", tables)
        self.assertIn("DeviceNetworkEvents", tables)
        self.assertEqual(len(tables), 4)

    # Requirement 3: Field Mapping Resolution
    # Test that the client can query the schema to map a legacy ArcSight field (like destinationAddress) to the active Sentinel equivalent (like DstIpAddr).
    def test_resolve_field_mapping_destination_address(self):
        client = SentinelClient(
            tenant_id=self.tenant_id,
            client_id=self.client_id,
            client_secret=self.client_secret,
            workspace_id=self.workspace_id,
        )
        resolved = client.resolve_field_mapping("destinationAddress", target_table="ASimProcessEventLogs")
        self.assertEqual(resolved, "DstIpAddr")

    def test_resolve_field_mapping_common_fields(self):
        client = SentinelClient(
            tenant_id=self.tenant_id,
            client_id=self.client_id,
            client_secret=self.client_secret,
            workspace_id=self.workspace_id,
        )
        self.assertEqual(client.resolve_field_mapping("sourceAddress", target_table="ASimProcessEventLogs"), "SrcIpAddr")
        self.assertEqual(client.resolve_field_mapping("deviceAction", target_table="ASimProcessEventLogs"), "EventResult")

    def test_resolve_field_mapping_unmapped_fallback(self):
        client = SentinelClient(
            tenant_id=self.tenant_id,
            client_id=self.client_id,
            client_secret=self.client_secret,
            workspace_id=self.workspace_id,
        )
        resolved = client.resolve_field_mapping("customUnknownField_s")
        self.assertEqual(resolved, "customUnknownField_s")


if __name__ == "__main__":
    unittest.main()

