"""
Unit tests for audit_store.py
"""

import os
import tempfile
import unittest
from backend.audit_store import AuditStore


class TestAuditStore(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_audit.db")
        self.store = AuditStore(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_log_and_retrieve_event(self):
        rec_id = self.store.log_event(
            rule_name="ADFind Recon",
            endpoint="/api/translate-direct",
            outcome="passed",
            provider="lm_studio",
            model="qwen2.5-coder",
            coverage_pct=100.0,
            details={"kql": "DeviceProcessEvents | ..."},
        )
        self.assertGreater(rec_id, 0)

        history = self.store.get_history(limit=10)
        self.assertEqual(len(history), 1)
        item = history[0]
        self.assertEqual(item["rule_name"], "ADFind Recon")
        self.assertEqual(item["outcome"], "passed")
        self.assertEqual(item["coverage_pct"], 100.0)
        self.assertEqual(item["details"]["kql"], "DeviceProcessEvents | ...")

    def test_get_stats(self):
        self.store.log_event(rule_name="Rule 1", endpoint="/api/test", outcome="passed", coverage_pct=100.0)
        self.store.log_event(rule_name="Rule 2", endpoint="/api/test", outcome="failed", coverage_pct=50.0)

        stats = self.store.get_stats()
        self.assertEqual(stats["total_events"], 2)
        self.assertEqual(stats["passed_count"], 1)
        self.assertEqual(stats["failed_count"], 1)
        self.assertEqual(stats["average_coverage_pct"], 75.0)


if __name__ == "__main__":
    unittest.main()

