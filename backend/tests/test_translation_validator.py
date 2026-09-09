"""
Unit tests for translation_validator.py
"""

import unittest
from backend.translation_validator import (
    ValidationResult,
    validate_query,
    is_in_negated_context,
)


class TestTranslationValidator(unittest.TestCase):

    def test_serialization_preserves_passed_property(self):
        """
        Regression test: Ensure 'passed' @property is properly serialized
        when calling .to_dict().
        """
        res = ValidationResult(
            target_language="KQL",
            required_terms_checked=["cmd.exe"],
            missing_required=[],
            exclusion_terms_checked=["service_account"],
            missing_exclusions=[],
            wrongly_included_as_match=[],
            coverage_pct=100.0,
        )
        self.assertTrue(res.passed)
        d = res.to_dict()
        self.assertIn("passed", d)
        self.assertEqual(d["passed"], True)

    def test_missing_required_term_fails(self):
        kql = """
        DeviceProcessEvents
        | where ProcessCommandLine has "powershell.exe"
        """
        res = validate_query(
            query_text=kql,
            required_terms=["powershell.exe", "Invoke-Mimikatz"],
            exclusion_terms=[],
            target_language="KQL",
        )
        self.assertFalse(res.passed)
        self.assertIn("Invoke-Mimikatz", res.missing_required)
        self.assertEqual(res.coverage_pct, 50.0)

    def test_exclusion_properly_negated_passes(self):
        kql = """
        DeviceProcessEvents
        | where ProcessCommandLine has "adfind.exe"
        | where AccountName != "service_account"
        """
        res = validate_query(
            query_text=kql,
            required_terms=["adfind.exe"],
            exclusion_terms=["service_account"],
            target_language="KQL",
        )
        self.assertTrue(res.passed)
        self.assertEqual(res.missing_exclusions, [])
        self.assertEqual(res.wrongly_included_as_match, [])
        self.assertEqual(res.coverage_pct, 100.0)

    def test_exclusion_unnegated_catches_wrongly_included(self):
        spl = """
        index=main process_name="adfind.exe" user="service_account"
        """
        res = validate_query(
            query_text=spl,
            required_terms=["adfind.exe"],
            exclusion_terms=["service_account"],
            target_language="SPL",
        )
        self.assertFalse(res.passed)
        self.assertIn("service_account", res.wrongly_included_as_match)

    def test_spl_negated_with_not(self):
        spl = """
        index=main process_name="adfind.exe" NOT (user="service_account")
        """
        res = validate_query(
            query_text=spl,
            required_terms=["adfind.exe"],
            exclusion_terms=["service_account"],
            target_language="SPL",
        )
        self.assertTrue(res.passed)


class TestKQLDeterministicValidation(unittest.TestCase):
    """
    Test suite for KQL deterministic regex validation:
    1. Table Identification (must begin with valid target table)
    2. Deterministic Exclusion Audit (where not(...), !=, !has, !has_any(...))
    3. Operator Validation (rejection of improperly injected SPL syntax)
    """

    # -------------------------------------------------------------------------
    # 1. Table Identification Tests
    # -------------------------------------------------------------------------

    def test_kql_valid_target_tables_pass(self):
        """KQL queries starting with valid schema tables should pass table validation."""
        valid_tables = [
            "DeviceProcessEvents",
            "DeviceNetworkEvents",
            "SecurityEvent",
            "CommonSecurityLog",
            "Syslog",
        ]
        for table in valid_tables:
            with self.subTest(table=table):
                kql = f"""
                {table}
                | where ProcessCommandLine has "powershell.exe"
                | where AccountName != "service_account"
                """
                res = validate_query(
                    query_text=kql,
                    required_terms=["powershell.exe"],
                    exclusion_terms=["service_account"],
                    target_language="KQL",
                )
                self.assertTrue(res.passed, f"Valid table {table} should pass validation")
                # Notes should not complain about missing or invalid table
                self.assertFalse(any("table" in n.lower() and "invalid" in n.lower() for n in res.notes))

    def test_kql_missing_table_fails(self):
        """KQL query starting directly with a pipe and no table name must fail."""
        kql_missing_table = """
        | where ProcessCommandLine has "powershell.exe"
        | where AccountName != "service_account"
        """
        res = validate_query(
            query_text=kql_missing_table,
            required_terms=["powershell.exe"],
            exclusion_terms=["service_account"],
            target_language="KQL",
        )
        self.assertFalse(res.passed, "KQL query missing target table must fail validation")
        self.assertTrue(
            any("table" in n.lower() for n in res.notes),
            f"Expected table identification error note in {res.notes}",
        )

    def test_kql_invalid_target_table_fails(self):
        """KQL query starting with an unrecognized / bogus table name must fail."""
        kql_invalid_table = """
        InvalidUnknownTableEvents
        | where ProcessCommandLine has "powershell.exe"
        | where AccountName != "service_account"
        """
        res = validate_query(
            query_text=kql_invalid_table,
            required_terms=["powershell.exe"],
            exclusion_terms=["service_account"],
            target_language="KQL",
        )
        self.assertFalse(res.passed, "KQL query with unknown table must fail validation")
        self.assertTrue(
            any("table" in n.lower() for n in res.notes),
            f"Expected invalid table error note in {res.notes}",
        )

    # -------------------------------------------------------------------------
    # 2. Operator Validation Tests (Rejection of Injected SPL Syntax)
    # -------------------------------------------------------------------------

    def test_kql_with_spl_eval_fails(self):
        """KQL query containing injected SPL '| eval' must fail operator validation."""
        kql = """
        DeviceProcessEvents
        | where ProcessCommandLine has "powershell.exe"
        | eval process=lower(ProcessCommandLine)
        | where AccountName != "service_account"
        """
        res = validate_query(
            query_text=kql,
            required_terms=["powershell.exe"],
            exclusion_terms=["service_account"],
            target_language="KQL",
        )
        self.assertFalse(res.passed, "KQL query with SPL '| eval' must fail validation")
        self.assertTrue(
            any("eval" in n.lower() or "spl" in n.lower() or "operator" in n.lower() for n in res.notes),
            f"Expected operator validation error in notes: {res.notes}",
        )

    def test_kql_with_spl_search_fails(self):
        """KQL query containing injected SPL 'search' or '| search' must fail operator validation."""
        kql = """
        DeviceProcessEvents
        | search ProcessCommandLine="*powershell.exe*"
        | where AccountName != "service_account"
        """
        res = validate_query(
            query_text=kql,
            required_terms=["powershell.exe"],
            exclusion_terms=["service_account"],
            target_language="KQL",
        )
        self.assertFalse(res.passed, "KQL query with SPL 'search' must fail validation")
        self.assertTrue(
            any("search" in n.lower() or "spl" in n.lower() or "operator" in n.lower() for n in res.notes),
            f"Expected operator validation error in notes: {res.notes}",
        )

    def test_kql_with_spl_rex_fails(self):
        """KQL query containing injected SPL '| rex' must fail operator validation."""
        kql = """
        DeviceProcessEvents
        | where ProcessCommandLine has "powershell.exe"
        | rex field=ProcessCommandLine "cmd=(?<command>.*)"
        | where AccountName != "service_account"
        """
        res = validate_query(
            query_text=kql,
            required_terms=["powershell.exe"],
            exclusion_terms=["service_account"],
            target_language="KQL",
        )
        self.assertFalse(res.passed, "KQL query with SPL '| rex' must fail validation")
        self.assertTrue(
            any("rex" in n.lower() or "spl" in n.lower() or "operator" in n.lower() for n in res.notes),
            f"Expected operator validation error in notes: {res.notes}",
        )

    def test_kql_valid_operators_pass(self):
        """KQL query using proper KQL operators (| where, | extend, | project) should pass."""
        kql = """
        DeviceProcessEvents
        | extend ProcName = tolower(FileName)
        | where ProcessCommandLine has "powershell.exe"
        | where AccountName != "service_account"
        | project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
        """
        res = validate_query(
            query_text=kql,
            required_terms=["powershell.exe"],
            exclusion_terms=["service_account"],
            target_language="KQL",
        )
        self.assertTrue(res.passed, "KQL with valid operators should pass validation")

    # -------------------------------------------------------------------------
    # 3. Deterministic Exclusion Audit Tests
    # -------------------------------------------------------------------------

    def test_kql_exclusion_not_equals_passes(self):
        """KQL query with '!=' negative logic must pass exclusion audit."""
        kql = """
        DeviceProcessEvents
        | where ProcessCommandLine has "mimikatz"
        | where InitiatingProcessAccountName != "system_admin"
        """
        res = validate_query(
            query_text=kql,
            required_terms=["mimikatz"],
            exclusion_terms=["system_admin"],
            target_language="KQL",
        )
        self.assertTrue(res.passed)
        self.assertEqual(res.missing_exclusions, [])
        self.assertEqual(res.wrongly_included_as_match, [])

    def test_kql_exclusion_not_has_passes(self):
        """KQL query with '!has' negative logic must pass exclusion audit."""
        kql = """
        DeviceProcessEvents
        | where ProcessCommandLine has "whoami.exe"
        | where ProcessCommandLine !has "test_script.ps1"
        """
        res = validate_query(
            query_text=kql,
            required_terms=["whoami.exe"],
            exclusion_terms=["test_script.ps1"],
            target_language="KQL",
        )
        self.assertTrue(res.passed)
        self.assertEqual(res.missing_exclusions, [])
        self.assertEqual(res.wrongly_included_as_match, [])

    def test_kql_exclusion_where_not_passes(self):
        """KQL query with 'where not(...)' negative logic must pass exclusion audit."""
        kql = """
        DeviceProcessEvents
        | where ProcessCommandLine has "rundll32.exe"
        | where not(AccountName in ("admin_dev", "build_agent"))
        """
        res = validate_query(
            query_text=kql,
            required_terms=["rundll32.exe"],
            exclusion_terms=["admin_dev"],
            target_language="KQL",
        )
        self.assertTrue(res.passed)
        self.assertEqual(res.missing_exclusions, [])
        self.assertEqual(res.wrongly_included_as_match, [])

    def test_kql_exclusion_not_has_any_passes(self):
        """KQL query with '!has_any(...)' negative logic must pass exclusion audit."""
        kql = """
        DeviceNetworkEvents
        | where RemotePort == 443
        | where RemoteUrl !has_any ("internal.corp", "trusted.domain")
        """
        res = validate_query(
            query_text=kql,
            required_terms=["443"],
            exclusion_terms=["internal.corp"],
            target_language="KQL",
        )
        self.assertTrue(res.passed)
        self.assertEqual(res.missing_exclusions, [])
        self.assertEqual(res.wrongly_included_as_match, [])

    def test_kql_exclusion_dropped_fails(self):
        """KQL query that completely drops an exclusion term must fail audit."""
        kql = """
        DeviceProcessEvents
        | where ProcessCommandLine has "powershell.exe"
        """
        res = validate_query(
            query_text=kql,
            required_terms=["powershell.exe"],
            exclusion_terms=["service_account"],
            target_language="KQL",
        )
        self.assertFalse(res.passed)
        self.assertIn("service_account", res.missing_exclusions)

    def test_kql_exclusion_unnegated_has_fails(self):
        """KQL query that turns an exclusion into a positive 'has' match must fail audit."""
        kql = """
        DeviceProcessEvents
        | where ProcessCommandLine has "powershell.exe"
        | where AccountName has "service_account"
        """
        res = validate_query(
            query_text=kql,
            required_terms=["powershell.exe"],
            exclusion_terms=["service_account"],
            target_language="KQL",
        )
        self.assertFalse(res.passed)
        self.assertIn("service_account", res.wrongly_included_as_match)

    def test_kql_exclusion_unnegated_has_any_fails(self):
        """KQL query that turns an exclusion into a positive 'has_any' match must fail audit."""
        kql = """
        DeviceProcessEvents
        | where ProcessCommandLine has "powershell.exe"
        | where AccountName has_any ("admin_dev", "backup_svc")
        """
        res = validate_query(
            query_text=kql,
            required_terms=["powershell.exe"],
            exclusion_terms=["admin_dev"],
            target_language="KQL",
        )
        self.assertFalse(res.passed)
        self.assertIn("admin_dev", res.wrongly_included_as_match)


if __name__ == "__main__":
    unittest.main()


