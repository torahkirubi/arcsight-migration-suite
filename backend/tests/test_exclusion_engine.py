"""
test_exclusion_engine.py - Unit tests for KQL Exclusion Engine & Auto-Mitigation Injection

Requirements tested:
1. Exclusion Appender: Target function apply_exclusions(raw_kql: str, entities: list) -> str in backend.telemetry_tuner.
2. KQL Injection Placement: Injects exclusion filter (e.g., | where Object !in ('10.0.0.5', 'svc-scanner'))
   before aggregate clauses like | summarize or | count.
3. Negative Logic Retention: Deterministic parity requirement ensuring negative operators (!in, !=, !has)
   are retained and never inverted into inclusive matches.
4. Edge Cases: Gracefully handles queries without aggregations, empty/None entity lists, and empty queries.
"""

import unittest
import re

try:
    from backend.telemetry_tuner import apply_exclusions
except ImportError:
    apply_exclusions = None


class TestExclusionEngine(unittest.TestCase):
    """Test suite for apply_exclusions in backend.telemetry_tuner."""

    def test_apply_exclusions_importable(self):
        """Assert apply_exclusions is importable from backend.telemetry_tuner."""
        self.assertIsNotNone(
            apply_exclusions,
            "apply_exclusions must be defined and importable from backend.telemetry_tuner",
        )
        self.assertTrue(
            callable(apply_exclusions),
            "apply_exclusions must be a callable function",
        )

    def test_apply_exclusions_multiple_entities_before_summarize(self):
        """
        Assert that providing entities injects a negative exclusion block
        (e.g., | where Object !in ('10.0.0.5', 'svc-scanner')) before | summarize.
        """
        if apply_exclusions is None:
            self.fail("apply_exclusions is not implemented in backend.telemetry_tuner")

        raw_kql = (
            "SecurityEvent\n"
            "| where EventID == 4625\n"
            "| summarize count() by TargetAccount"
        )
        entities = ["10.0.0.5", "svc-scanner"]

        tuned_kql = apply_exclusions(raw_kql, entities)

        # 1. Assert entities are present in tuned KQL
        self.assertIn("10.0.0.5", tuned_kql)
        self.assertIn("svc-scanner", tuned_kql)

        # 2. Assert negative logic retention (!in, !=, !has)
        self.assertTrue(
            "!in" in tuned_kql or "!has" in tuned_kql or "!=" in tuned_kql,
            f"Exclusion block must use negative operator (!in, !=, !has). Got: {tuned_kql}",
        )

        # 3. Assert deterministic parity: No positive inclusion for exclusion terms
        # Ensure we don't produce '| where Object in (...)' without the negation prefix
        self.assertNotRegex(
            tuned_kql,
            r"\|\s*where\s+\w+\s+in\s*\(.*10\.0\.0\.5",
            "Exclusion filter must NOT be inverted into a positive 'in' clause",
        )

        # 4. Assert placement before | summarize
        summarize_idx = tuned_kql.find("| summarize")
        exclusion_match = re.search(r"\|\s*where\s+.*(!in|!=|!has)", tuned_kql)
        self.assertIsNotNone(exclusion_match, f"Expected '| where ... (!in|!=|!has)' clause in: {tuned_kql}")
        self.assertNotEqual(summarize_idx, -1, "Expected '| summarize' clause in tuned KQL")
        self.assertLess(
            exclusion_match.start(),
            summarize_idx,
            "Exclusion block must be injected BEFORE '| summarize'",
        )

    def test_apply_exclusions_before_count_aggregate(self):
        """Assert that the exclusion block is injected before '| count'."""
        if apply_exclusions is None:
            self.fail("apply_exclusions is not implemented in backend.telemetry_tuner")

        raw_kql = (
            "SigninLogs\n"
            "| where ResultType != 0\n"
            "| count"
        )
        entities = ["192.168.1.100"]

        tuned_kql = apply_exclusions(raw_kql, entities)

        self.assertIn("192.168.1.100", tuned_kql)
        count_idx = tuned_kql.find("| count")
        exclusion_match = re.search(r"\|\s*where\s+.*(!in|!=|!has)", tuned_kql)
        self.assertIsNotNone(exclusion_match, f"Expected exclusion clause in: {tuned_kql}")
        self.assertNotEqual(count_idx, -1, "Expected '| count' clause in tuned KQL")
        self.assertLess(
            exclusion_match.start(),
            count_idx,
            "Exclusion block must be injected BEFORE '| count'",
        )

    def test_apply_exclusions_without_aggregations(self):
        """Assert that if no aggregate clause exists, the exclusion is cleanly appended."""
        if apply_exclusions is None:
            self.fail("apply_exclusions is not implemented in backend.telemetry_tuner")

        raw_kql = (
            "SecurityEvent\n"
            "| where EventID == 4625"
        )
        entities = ["10.0.0.5", "svc-scanner"]

        tuned_kql = apply_exclusions(raw_kql, entities)

        self.assertTrue(tuned_kql.startswith("SecurityEvent"))
        self.assertIn("| where EventID == 4625", tuned_kql)
        self.assertIn("10.0.0.5", tuned_kql)
        self.assertIn("svc-scanner", tuned_kql)
        self.assertTrue("!in" in tuned_kql or "!=" in tuned_kql or "!has" in tuned_kql)

    def test_apply_exclusions_empty_or_none_entities(self):
        """Assert that passing an empty list or None returns the original query unchanged."""
        if apply_exclusions is None:
            self.fail("apply_exclusions is not implemented in backend.telemetry_tuner")

        raw_kql = "SecurityEvent | where EventID == 4625 | summarize count()"

        self.assertEqual(apply_exclusions(raw_kql, []), raw_kql)
        self.assertEqual(apply_exclusions(raw_kql, None), raw_kql)

    def test_apply_exclusions_empty_kql(self):
        """Assert that passing empty or whitespace KQL returns empty string or unchanged."""
        if apply_exclusions is None:
            self.fail("apply_exclusions is not implemented in backend.telemetry_tuner")

        self.assertEqual(apply_exclusions("", ["10.0.0.5"]).strip(), "")
        self.assertEqual(apply_exclusions(None, ["10.0.0.5"]), "")


if __name__ == "__main__":
    unittest.main()

