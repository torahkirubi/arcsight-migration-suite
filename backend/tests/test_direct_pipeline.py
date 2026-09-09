"""
test_direct_pipeline.py - Integration test for direct path translation & git-ready export
"""

import unittest
from backend.arcsight_parser import parse_arcsight_rule
from backend.direct_translate_prompts import (
    DIRECT_TRANSLATE_SYSTEM_PROMPT,
    FIELD_MAPPING_CHEAT_SHEET,
    build_direct_translate_prompt,
    extract_queries_from_response,
)
from backend.translation_validator import validate_translation_bundle
from backend.git_exporter import generate_git_ready_text


SAMPLE_ARCSIGHT_RULE = """Rule Name: ADFind Active Directory Reconnaissance Detected
Priority: 7
Matching 5 events in 10 Minutes
groupByFields: deviceHostName, destinationUserName

Conditions:
(attackerServiceName EQ "cmd.exe" And (deviceCustomString1 Contains "adfind.exe" Or deviceCustomString2 Contains "adfind.exe" And (destinationUserName NE "service_account" And (destinationPort NE "80"

Actions:
SetEventField(name, "ADFind Active Directory Reconnaissance Detected")
SetEventField(basePriority, 7)
SetEventField(eventAnnotationStage, <Resource URI="/All Stages/MITRE Tactics/Discovery" />)
"""

MOCK_LLM_OUTPUT = """Here are the translated KQL and SPL queries:

```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("cmd.exe", "adfind.exe")
| where InitiatingProcessAccountName != "service_account"
| where RemotePort != 80
| summarize EventCount = count() by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 10m)
| where EventCount >= 5
```

```spl
index=main (process="*cmd.exe*" OR CommandLine="*adfind.exe*") NOT (user="service_account") NOT (dest_port=80)
| bin _time span=10m
| stats count as EventCount by dest, user, _time
| search EventCount >= 5
```
"""


class TestDirectPipeline(unittest.TestCase):

    def test_direct_path_end_to_end(self):
        # 1. Deterministic Extraction
        parsed = parse_arcsight_rule(SAMPLE_ARCSIGHT_RULE)
        self.assertEqual(parsed.rule_name, "ADFind Active Directory Reconnaissance Detected")
        self.assertEqual(parsed.severity, "High")
        self.assertEqual(parsed.priority, 7)
        self.assertEqual(parsed.mitre_tactic, "Discovery")
        self.assertEqual(parsed.mitre_source, "extracted from rule")
        self.assertEqual(parsed.frequency.event_count, 5)
        self.assertEqual(parsed.frequency.time_window_value, 10)
        self.assertIn("cmd.exe", parsed.required_terms)
        self.assertIn("adfind.exe", parsed.required_terms)
        self.assertIn("service_account", parsed.exclusion_terms)

        # 2. Extract queries from LLM output
        kql, spl = extract_queries_from_response(MOCK_LLM_OUTPUT)
        self.assertTrue(len(kql) > 20)
        self.assertTrue(len(spl) > 20)

        # 3. Deterministic Coverage Validation
        bundle = validate_translation_bundle(kql, spl, parsed)
        self.assertTrue(bundle["passed"])
        self.assertEqual(bundle["kql"]["passed"], True)
        self.assertEqual(bundle["spl"]["passed"], True)
        self.assertEqual(bundle["overall_coverage_pct"], 100.0)

        # 4. Generate Git-Ready Runbook with Human MDE verdict
        runbook = generate_git_ready_text(
            rule_name=parsed.rule_name,
            severity=parsed.severity,
            priority=parsed.priority,
            mitre_tactic=parsed.mitre_tactic,
            mitre_source=parsed.mitre_source,
            mitre_uri=parsed.mitre_uri,
            frequency_str=parsed.frequency.raw_frequency,
            group_by=parsed.group_by_fields,
            kql_query=kql,
            kql_validation=bundle["kql"],
            spl_query=spl,
            spl_validation=bundle["spl"],
            threat_analysis={"threat_summary": "ADFind enumeration against domain controllers"},
            mde_verdict="Partial / Custom KQL Rule Required (Complementary)",
            mde_notes="Default MDE detects execution but does not alert on specific query arguments.",
        )

        self.assertIn("ADFind Active Directory Reconnaissance Detected", runbook)
        self.assertIn("Discovery (Trustworthiness: extracted from rule)", runbook)
        self.assertIn("VERDICT: Partial / Custom KQL Rule Required (Complementary)", runbook)
        self.assertIn("KQL Coverage Validation: PASSED", runbook)
        self.assertIn("SPL Coverage Validation: PASSED", runbook)

    def test_direct_translate_prompts_fidelity_directives(self):
        """Verify strict directives for logical operator fidelity and field mapping multi-term grouping."""
        expected_directive = (
            "You MUST preserve all negation and exclusion logic. "
            "If the ArcSight rule excludes a string, IP, or condition, the resulting KQL and SPL "
            "MUST use explicit negation (e.g., NOT, !=, not in()). Do not invert exclusion logic into inclusive matches."
        )
        expected_field_mapping = "Ensure multi-term exclusions are properly grouped and negated according to the target language's order of operations."

        # Verify in system prompt
        self.assertIn("STRICT DIRECTIVES - LOGICAL OPERATOR FIDELITY", DIRECT_TRANSLATE_SYSTEM_PROMPT)
        self.assertIn(expected_directive, DIRECT_TRANSLATE_SYSTEM_PROMPT)
        self.assertIn(expected_field_mapping, DIRECT_TRANSLATE_SYSTEM_PROMPT)

        # Verify in field mapping cheat sheet
        self.assertIn(expected_field_mapping, FIELD_MAPPING_CHEAT_SHEET)

        # Verify in build_direct_translate_prompt
        user_prompt = build_direct_translate_prompt(
            rule_name="Test Rule",
            severity="High",
            raw_condition='destinationUserName NE "admin"',
            frequency_str="Matching 1 events in 5 Minutes",
            group_by=["deviceHostName"],
            mitre_tactic="Discovery",
            required_terms=["cmd.exe"],
            exclusion_terms=["admin", "service_account"],
        )
        self.assertIn("Strict Directives (Logical Operator Fidelity):", user_prompt)
        self.assertIn(expected_directive, user_prompt)
        self.assertIn(expected_field_mapping, user_prompt)
        self.assertIn("Identified Exclusion Filters (CRITICAL - MUST BE EXPLICITLY NEGATED):", user_prompt)
        self.assertIn("admin, service_account", user_prompt)

    def test_direct_translate_prompts_spl_syntax_constraints(self):
        """Verify SPL syntax constraints for wildcard filtering and time handling."""
        expected_wildcard = (
            "When matching fields against patterns with wildcards (*) using the IN operator, "
            "always use | search Field IN (...) rather than | where. "
            "Splunk treats asterisks as literal characters inside where clauses."
        )
        expected_time = (
            "Do not append runtime relative time calculations like | where _time >= relative_time(...) "
            "unless explicitly requested. Rely on base search parameters (e.g., earliest=-1m) "
            "or let the SIEM execution schedule handle windowing."
        )

        # Verify in system prompt
        self.assertIn("STRICT DIRECTIVES - SPL SYNTAX CONSTRAINTS:", DIRECT_TRANSLATE_SYSTEM_PROMPT)
        self.assertIn(expected_wildcard, DIRECT_TRANSLATE_SYSTEM_PROMPT)
        self.assertIn(expected_time, DIRECT_TRANSLATE_SYSTEM_PROMPT)

        # Verify in field mapping cheat sheet
        self.assertIn(expected_wildcard, FIELD_MAPPING_CHEAT_SHEET)
        self.assertIn(expected_time, FIELD_MAPPING_CHEAT_SHEET)

        # Verify in user prompt generated by build_direct_translate_prompt
        user_prompt = build_direct_translate_prompt(
            rule_name="Test SPL Rule",
            severity="Medium",
            raw_condition='CommandLine IN ("*powershell*", "*cmd*")',
            frequency_str="Matching 1 events in 5 Minutes",
            group_by=["host"],
        )
        self.assertIn("Strict Directives (SPL Syntax Constraints):", user_prompt)
        self.assertIn(expected_wildcard, user_prompt)
        self.assertIn(expected_time, user_prompt)


if __name__ == "__main__":
    unittest.main()

