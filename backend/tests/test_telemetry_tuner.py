"""
test_telemetry_tuner.py - Unit tests for historical telemetry threshold tuning & Sentinel KQL execution
"""

import unittest
from unittest.mock import patch, MagicMock

from backend.sentinel_client import SentinelClient
from backend.telemetry_tuner import calculate_dynamic_threshold


class TestTelemetryTuner(unittest.TestCase):

    def setUp(self):
        self.client = SentinelClient(
            tenant_id="mock-tenant",
            client_id="mock-client",
            client_secret="mock-secret",
            workspace_id="mock-workspace",
        )

    # Requirement 1: KQL Execution Mock
    # Test that SentinelClient has a new method execute_kql_query(query_text, timespan_days=7)
    # that returns a mock row count (e.g., simulating 150 historical events found).
    def test_sentinel_client_execute_kql_query(self):
        """Verify SentinelClient has execute_kql_query method returning row count and metadata."""
        query = "DeviceProcessEvents | where ProcessCommandLine has 'adfind.exe'"
        result = self.client.execute_kql_query(query, timespan_days=7)

        self.assertIsInstance(result, dict)
        self.assertIn("row_count", result)
        self.assertIn("timespan_days", result)
        self.assertEqual(result["timespan_days"], 7)
        self.assertGreaterEqual(result["row_count"], 0)

    @patch.object(SentinelClient, "execute_kql_query")
    def test_sentinel_client_execute_kql_query_mocked_count(self, mock_exec):
        """Verify SentinelClient returns simulated 150 historical events."""
        mock_exec.return_value = {
            "success": True,
            "row_count": 150,
            "timespan_days": 7,
            "query": "DeviceProcessEvents | count",
        }
        res = self.client.execute_kql_query("DeviceProcessEvents | count", timespan_days=7)
        self.assertEqual(res["row_count"], 150)
        self.assertEqual(res["timespan_days"], 7)

    # Requirement 2: Threshold Calculation
    # Test a new function calculate_dynamic_threshold(baseline_event_count, static_rule_threshold).
    # If the ArcSight rule triggers at 5 events, but the 7-day historical baseline returns 150 events,
    # it should recommend a new threshold safely above the baseline noise (e.g., 150 + buffer).
    def test_calculate_dynamic_threshold_elevated_baseline(self):
        """When baseline noise exceeds static threshold, recommend threshold above baseline."""
        baseline_event_count = 150
        static_rule_threshold = 5

        recommendation = calculate_dynamic_threshold(
            baseline_event_count=baseline_event_count,
            static_rule_threshold=static_rule_threshold,
        )

        self.assertGreater(recommendation["suggested_threshold"], baseline_event_count)
        self.assertEqual(recommendation["original_threshold"], static_rule_threshold)

    def test_calculate_dynamic_threshold_low_baseline(self):
        """When baseline noise is zero or lower than static threshold, retain static threshold."""
        baseline_event_count = 0
        static_rule_threshold = 5

        recommendation = calculate_dynamic_threshold(
            baseline_event_count=baseline_event_count,
            static_rule_threshold=static_rule_threshold,
        )

        self.assertEqual(recommendation["suggested_threshold"], static_rule_threshold)
        self.assertEqual(recommendation["original_threshold"], static_rule_threshold)

    # Requirement 3: Tuning Recommendation Output
    # Test that the function returns a structured dictionary containing original_threshold,
    # suggested_threshold, and a tuning_rationale string.
    def test_tuning_recommendation_output_structure(self):
        """Verify output dictionary structure and tuning_rationale content."""
        recommendation = calculate_dynamic_threshold(
            baseline_event_count=150,
            static_rule_threshold=5,
        )

        self.assertIsInstance(recommendation, dict)
        self.assertIn("original_threshold", recommendation)
        self.assertIn("suggested_threshold", recommendation)
        self.assertIn("tuning_rationale", recommendation)

        self.assertEqual(recommendation["original_threshold"], 5)
        self.assertIsInstance(recommendation["tuning_rationale"], str)
        self.assertTrue(len(recommendation["tuning_rationale"]) > 10)
        self.assertIn("150", recommendation["tuning_rationale"])


if __name__ == "__main__":
    unittest.main()

