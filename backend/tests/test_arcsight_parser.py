"""
Unit tests for arcsight_parser.py
"""

import unittest
from backend.arcsight_parser import (
    map_priority_to_severity,
    extract_rule_name,
    extract_priority,
    extract_frequency,
    extract_group_by,
    extract_mitre_tactic,
    parse_condition_clauses,
    parse_arcsight_rule,
)


class TestArcSightParser(unittest.TestCase):

    def test_priority_mapping(self):
        self.assertEqual(map_priority_to_severity(0), "Low")
        self.assertEqual(map_priority_to_severity(3), "Low")
        self.assertEqual(map_priority_to_severity(4), "Medium")
        self.assertEqual(map_priority_to_severity(6), "Medium")
        self.assertEqual(map_priority_to_severity(7), "High")
        self.assertEqual(map_priority_to_severity(8), "High")
        self.assertEqual(map_priority_to_severity(9), "Critical")
        self.assertEqual(map_priority_to_severity(10), "Critical")

    def test_mitre_tactic_extraction_present(self):
        sample = """
        SetEventField(name, "ADFind Reconnaissance")
        SetEventField(eventAnnotationStage, <Resource URI="/All Stages/MITRE Tactics/Discovery" />)
        """
        tactic, source, uri = extract_mitre_tactic(sample)
        self.assertEqual(tactic, "Discovery")
        self.assertEqual(source, "extracted from rule")
        self.assertIn("MITRE Tactics/Discovery", uri)

    def test_mitre_tactic_extraction_missing(self):
        sample = """
        SetEventField(name, "Plain Rule Without Stage")
        """
        tactic, source, uri = extract_mitre_tactic(sample)
        self.assertIsNone(tactic)
        self.assertEqual(source, "missing")
        self.assertIsNone(uri)

    def test_dropped_parentheses_edge_case(self):
        """
        Tests the critical edge case where ArcSight rule exports drop closing
        parentheses per clause (e.g. (attackerServiceName EQ "cmd.exe" And (deviceCustomString1 Contains "adfind.exe")
        """
        malformed_condition = """
        (attackerServiceName EQ "cmd.exe" And (deviceCustomString1 Contains "adfind.exe" Or deviceCustomString2 Contains "adfind.exe" And destinationPort NE "80"
        """
        clauses, req_terms, excl_terms, fields = parse_condition_clauses(malformed_condition)

        # Clauses should be cleanly extracted without paren errors
        self.assertTrue(len(clauses) >= 3)
        self.assertIn("cmd.exe", req_terms)
        self.assertIn("adfind.exe", req_terms)
        self.assertIn("80", excl_terms)
        self.assertIn("attackerServiceName", fields)
        self.assertIn("destinationPort", fields)

    def test_full_rule_parse(self):
        sample_rule = """
        <Rule>
          <Name>ADFind Active Directory Reconnaissance</Name>
          <Priority>7</Priority>
          <Conditions>
            (attackerServiceName EQ "cmd.exe" And (deviceCustomString1 Contains "adfind.exe" Or deviceCustomString2 Contains "adfind.exe") And (destinationUserName NE "service_account")
          </Conditions>
          <Actions>
            SetEventField(name, "ADFind Active Directory Reconnaissance")
            SetEventField(basePriority, 7)
            SetEventField(eventAnnotationStage, <Resource URI="/All Stages/MITRE Tactics/Discovery" />)
          </Actions>
          <Aggregation>
            Matching 5 events in 10 Minutes
            groupByFields: deviceHostName, destinationUserName
          </Aggregation>
        </Rule>
        """
        parsed = parse_arcsight_rule(sample_rule)
        self.assertEqual(parsed.rule_name, "ADFind Active Directory Reconnaissance")
        self.assertEqual(parsed.priority, 7)
        self.assertEqual(parsed.severity, "High")
        self.assertEqual(parsed.mitre_tactic, "Discovery")
        self.assertEqual(parsed.mitre_source, "extracted from rule")
        self.assertEqual(parsed.frequency.event_count, 5)
        self.assertEqual(parsed.frequency.time_window_value, 10)
        self.assertEqual(parsed.frequency.time_window_unit, "Minutes")
        self.assertEqual(parsed.group_by_fields, ["deviceHostName", "destinationUserName"])
        self.assertIn("cmd.exe", parsed.required_terms)
        self.assertIn("adfind.exe", parsed.required_terms)
        self.assertIn("service_account", parsed.exclusion_terms)

    def test_contains_objectcategory_not_captured_as_exclusion(self):
        """Verify standard Contains clauses (e.g. objectcategory=) are NOT captured as exclusions."""
        sample_rule = """
        Rule Name: AD LDAP Search Discovery
        Priority: 6
        Conditions:
        (attackerServiceName EQ "cmd.exe" And (deviceCustomString1 Contains "adfind.exe" Or deviceCustomString2 Contains "objectcategory=" And(!Contains(deviceProcessName, "system") And (destinationUserName NE "service_account" And (destinationPort NE "80")))))
        """
        parsed = parse_arcsight_rule(sample_rule)
        # objectcategory= must be in required_terms, NOT exclusion_terms
        self.assertIn("objectcategory=", parsed.required_terms)
        self.assertNotIn("objectcategory=", parsed.exclusion_terms)

        # Terms following negation operators must be in exclusion_terms
        self.assertIn("system", parsed.exclusion_terms)
        self.assertIn("service_account", parsed.exclusion_terms)
        self.assertIn("80", parsed.exclusion_terms)
        self.assertNotIn("system", parsed.required_terms)

    def test_exclusion_extraction_prefix_and_infix_negation(self):
        """Verify both prefix !Contains(...) and infix !Contains extract exclusions accurately."""
        sample_rule = """
        Rule Name: Test Negation Styles
        Priority: 5
        Conditions:
        (deviceProcessName !Contains "evil.exe" And !Contains(destinationUserName, "admin") And deviceCustomString1 Contains "standard_search")
        """
        parsed = parse_arcsight_rule(sample_rule)
        self.assertIn("evil.exe", parsed.exclusion_terms)
        self.assertIn("admin", parsed.exclusion_terms)
        self.assertIn("standard_search", parsed.required_terms)
        self.assertNotIn("standard_search", parsed.exclusion_terms)


class TestArcSightActiveList(unittest.TestCase):
    """
    Test suite for ArcSight ActiveList extraction:
    1. Detect XML <Conditions> containing InActiveList operations.
    2. Extract ActiveList name (e.g., 'Malicious IPs', 'Terminated Users')
       and evaluated event field (e.g., 'destinationAddress', 'sourceUserName').
    3. Store extracted lookups in active_lists: List[Dict] on returned ParsedRule object.
    """

    def test_single_active_list_extraction(self):
        """Extract a single InActiveList lookup from XML Conditions."""
        sample_rule = """
        <Rule>
          <Name>Malicious Destination Communication</Name>
          <Priority>8</Priority>
          <Conditions>
            (InActiveList(destinationAddress, "Malicious IPs"))
          </Conditions>
          <Actions>
            SetEventField(name, "Malicious Destination Communication")
          </Actions>
        </Rule>
        """
        parsed = parse_arcsight_rule(sample_rule)
        self.assertTrue(hasattr(parsed, "active_lists"), "Parsed rule must have active_lists attribute")
        self.assertEqual(len(parsed.active_lists), 1)
        lookup = parsed.active_lists[0]
        self.assertEqual(lookup["name"], "Malicious IPs")
        self.assertEqual(lookup["field"], "destinationAddress")

    def test_multiple_active_list_lookups(self):
        """Extract multiple InActiveList lookups from compound XML Conditions."""
        sample_rule = """
        <Rule>
          <Name>Suspicious User and Destination</Name>
          <Priority>7</Priority>
          <Conditions>
            (InActiveList(destinationAddress, "Malicious IPs") And InActiveList(sourceUserName, "Terminated Users"))
          </Conditions>
        </Rule>
        """
        parsed = parse_arcsight_rule(sample_rule)
        self.assertTrue(hasattr(parsed, "active_lists"), "Parsed rule must have active_lists attribute")
        self.assertEqual(len(parsed.active_lists), 2)

        # Check first lookup
        self.assertEqual(parsed.active_lists[0]["name"], "Malicious IPs")
        self.assertEqual(parsed.active_lists[0]["field"], "destinationAddress")

        # Check second lookup
        self.assertEqual(parsed.active_lists[1]["name"], "Terminated Users")
        self.assertEqual(parsed.active_lists[1]["field"], "sourceUserName")

    def test_active_list_with_mixed_clauses(self):
        """Extract ActiveList lookups when mixed with regular boolean condition clauses."""
        sample_rule = """
        <Rule>
          <Name>ActiveList Mixed With Standard Clauses</Name>
          <Priority>7</Priority>
          <Conditions>
            (attackerServiceName EQ "cmd.exe" And InActiveList(destinationAddress, "Malicious IPs") And destinationPort NE "80")
          </Conditions>
        </Rule>
        """
        parsed = parse_arcsight_rule(sample_rule)
        self.assertTrue(hasattr(parsed, "active_lists"), "Parsed rule must have active_lists attribute")
        self.assertEqual(len(parsed.active_lists), 1)
        self.assertEqual(parsed.active_lists[0]["name"], "Malicious IPs")
        self.assertEqual(parsed.active_lists[0]["field"], "destinationAddress")
        # Standard required terms and exclusions must still be extracted
        self.assertIn("cmd.exe", parsed.required_terms)
        self.assertIn("80", parsed.exclusion_terms)

    def test_active_list_absent_returns_empty_list(self):
        """Rules without ActiveList operations must return an empty list for active_lists."""
        sample_rule = """
        <Rule>
          <Name>Standard Rule Without ActiveList</Name>
          <Priority>5</Priority>
          <Conditions>
            (attackerServiceName EQ "powershell.exe" And destinationPort EQ "443")
          </Conditions>
        </Rule>
        """
        parsed = parse_arcsight_rule(sample_rule)
        self.assertTrue(hasattr(parsed, "active_lists"), "Parsed rule must have active_lists attribute")
        self.assertEqual(parsed.active_lists, [])

    def test_active_list_syntax_variations(self):
        """Extract ActiveList lookups with whitespace or single-quote formatting variations."""
        sample_rule = """
        <Rule>
          <Name>Whitespace and Single Quote ActiveList</Name>
          <Priority>6</Priority>
          <Conditions>
            ( InActiveList ( destinationAddress , 'Malicious IPs' ) )
          </Conditions>
        </Rule>
        """
        parsed = parse_arcsight_rule(sample_rule)
        self.assertTrue(hasattr(parsed, "active_lists"), "Parsed rule must have active_lists attribute")
        self.assertEqual(len(parsed.active_lists), 1)
        self.assertEqual(parsed.active_lists[0]["name"], "Malicious IPs")
        self.assertEqual(parsed.active_lists[0]["field"], "destinationAddress")


if __name__ == "__main__":
    unittest.main()



