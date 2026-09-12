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

    def test_apply_exclusions_default_target_field_is_computer(self):
        """Assert that apply_exclusions uses 'Computer' by default instead of generic 'Object'."""
        raw_kql = "SecurityEvent | summarize count()"
        tuned = apply_exclusions(raw_kql, ["HOST-1", "HOST-2"])
        self.assertIn("| where Computer !in ('HOST-1', 'HOST-2')", tuned)
        self.assertNotIn("Object", tuned)

    def test_apply_exclusions_explicit_target_field(self):
        """Assert that apply_exclusions respects an explicitly specified target_field."""
        raw_kql = "DeviceProcessEvents | count"
        tuned = apply_exclusions(raw_kql, ["powershell.exe", "cmd.exe"], target_field="ProcessName")
        self.assertIn("| where ProcessName !in ('powershell.exe', 'cmd.exe')", tuned)
        self.assertNotIn("Object", tuned)

    def test_apply_exclusions_detects_account_name_when_query_mentions_account(self):
        """Assert that apply_exclusions uses 'AccountName' when query mentions AccountName and entities match accounts."""
        raw_kql = "SecurityEvent | where AccountName != '' | summarize count() by AccountName"
        tuned = apply_exclusions(raw_kql, ["svc-scanner", "svc-backup"])
        self.assertIn("| where AccountName !in ('svc-scanner', 'svc-backup')", tuned)
        self.assertNotIn("Object", tuned)
        self.assertNotIn("Computer", tuned)

    def test_apply_exclusions_dict_entities(self):
        """Assert that apply_exclusions unpacks dictionary entities into column-specific clauses."""
        raw_kql = (
            "SecurityEvents_CL\n"
            "| where TimeGenerated > ago(7d)\n"
            "| summarize AlertCount=count() by Computer, AccountName, ProcessName, CommandLine\n"
            "| order by AlertCount desc"
        )
        entities = [
            {"AccountName": "svc-scanner"},
            {"AccountName": "svc-backup"},
            {"Computer": "SRV-01.corp.local"},
            {"CommandLine": "net.exe user /domain"},
        ]
        tuned = apply_exclusions(raw_kql, entities)

        # 1. Assert column-specific clauses are generated
        self.assertIn("| where AccountName !in ('svc-scanner', 'svc-backup')", tuned)
        self.assertIn("| where Computer !in ('SRV-01.corp.local')", tuned)
        self.assertIn("| where CommandLine !in ('net.exe user /domain')", tuned)

        # 2. Assert raw dictionaries are not stringified into KQL
        self.assertNotIn("{'AccountName'", tuned)
        self.assertNotIn("Object", tuned)

        # 3. Assert negative logic retention
        self.assertIn("!in", tuned)
        self.assertNotRegex(tuned, r"\|\s*where\s+\w+\s+in\s*\(", "Negative logic must not be inverted into inclusive match")

        # 4. Assert placement before summarize
        summarize_idx = tuned.find("| summarize")
        self.assertNotEqual(summarize_idx, -1)
        for clause in [
            "| where AccountName !in ('svc-scanner', 'svc-backup')",
            "| where Computer !in ('SRV-01.corp.local')",
            "| where CommandLine !in ('net.exe user /domain')",
        ]:
            clause_idx = tuned.find(clause)
            self.assertNotEqual(clause_idx, -1, f"Missing clause: {clause}")
            self.assertLess(clause_idx, summarize_idx, f"Clause must be injected before | summarize: {clause}")

    def test_apply_exclusions_mixed_entities(self):
        """Assert that apply_exclusions handles a mixed list of dicts and plain strings."""
        raw_kql = (
            "SecurityEvents_CL\n"
            "| summarize count() by Computer, AccountName, CommandLine"
        )
        entities = [
            {"AccountName": "svc-scanner"},
            "DC-01.corp.local",
            {"CommandLine": "powershell.exe -enc <base64>"},
        ]
        tuned = apply_exclusions(raw_kql, entities)

        self.assertIn("| where AccountName !in ('svc-scanner')", tuned)
        self.assertIn("| where Computer !in ('DC-01.corp.local')", tuned)
        self.assertIn("| where CommandLine !in ('powershell.exe -enc <base64>')", tuned)
        self.assertNotIn("{'AccountName'", tuned)

    def test_apply_exclusions_escapes_single_quotes(self):
        """Assert that single quotes within entity values are escaped properly."""
        raw_kql = "SecurityEvents_CL | summarize count()"
        entities = [
            {"AccountName": "svc-o'reilly"},
            {"CommandLine": "cmd.exe /c echo 'test'"},
        ]
        tuned = apply_exclusions(raw_kql, entities)

        self.assertIn(r"svc-o\'reilly", tuned)
        self.assertIn(r"cmd.exe /c echo \'test\'", tuned)
        self.assertIn("!in", tuned)

    def test_apply_exclusions_handles_stringified_dicts_defensively(self):
        """Assert that apply_exclusions defensively unpacks stringified dictionaries."""
        raw_kql = "SecurityEvents_CL | summarize count()"
        entities = [
            "{'AccountName': 'svc-scanner'}",
            '{"Computer": "SRV-02.corp.local"}',
        ]
        tuned = apply_exclusions(raw_kql, entities)

        self.assertIn("| where AccountName !in ('svc-scanner')", tuned)
        self.assertIn("| where Computer !in ('SRV-02.corp.local')", tuned)
        self.assertNotIn("{'AccountName'", tuned)
        self.assertNotIn('{"Computer"', tuned)

    def test_apply_exclusions_parses_labeled_entities_by_column(self):
        """Field labels from an LLM must not become part of KQL values."""
        raw_kql = (
            "SecurityEvents_CL\n"
            "| where TimeGenerated > ago(7d)\n"
            "| summarize AlertCount=count() by Computer, AccountName, ProcessName, CommandLine\n"
            "| order by AlertCount desc"
        )
        entities = [
            "AccountName: svc-scanner",
            "AccountName: svc-backup",
            "AccountName: local_daemon",
            "Computer: DC-01.corp.local",
            "Computer: SRV-01.corp.local",
            "Computer: SRV-02.corp.local",
            "Computer: SRV-03.corp.local",
        ]
        tuned = apply_exclusions(raw_kql, entities)

        self.assertIn(
            "| where AccountName !in ('svc-scanner', 'svc-backup', 'local_daemon')",
            tuned,
        )
        self.assertIn(
            "| where Computer !in ('DC-01.corp.local', 'SRV-01.corp.local', 'SRV-02.corp.local', 'SRV-03.corp.local')",
            tuned,
        )
        self.assertNotIn("AccountName: ", tuned)
        self.assertNotIn("Computer: ", tuned)


    def test_apply_exclusions_compound_entity_dictionaries(self):
        """Assert that compound entity dictionaries generate | where not (<cond1> and <cond2>) clauses."""
        raw_kql = (
            "SecurityEvents_CL\n"
            "| where TimeGenerated > ago(7d)\n"
            "| summarize AlertCount=count() by Computer, AccountName, ProcessName, CommandLine\n"
            "| order by AlertCount desc"
        )
        entities = [
            {"AccountName": "svc-scanner", "CommandLine": "net.exe user /domain"},
            {"AccountName": "svc-backup", "CommandLine": "cmd.exe /c whoami"},
            {"Computer": "DC-01.corp.local"},
        ]
        tuned = apply_exclusions(raw_kql, entities)

        # 1. Assert compound negative expressions are generated
        self.assertIn("| where not (AccountName == 'svc-scanner' and CommandLine has 'net.exe user /domain')", tuned)
        self.assertIn("| where not (AccountName == 'svc-backup' and CommandLine has 'cmd.exe /c whoami')", tuned)
        self.assertIn("| where Computer !in ('DC-01.corp.local')", tuned)

        # 2. Assert no literal { or } characters are inside quotes in KQL
        self.assertNotIn("{'AccountName'", tuned)
        self.assertNotIn("{'Computer'", tuned)
        self.assertNotIn("Object", tuned)

        # 3. Assert negative logic retention
        self.assertIn("not (", tuned)
        self.assertIn("!in", tuned)

        # 4. Assert placement before summarize
        summarize_idx = tuned.find("| summarize")
        self.assertNotEqual(summarize_idx, -1)
        compound_idx = tuned.find("| where not (AccountName == 'svc-scanner'")
        self.assertLess(compound_idx, summarize_idx)


if __name__ == "__main__":
    unittest.main()
