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


if __name__ == "__main__":
    unittest.main()

