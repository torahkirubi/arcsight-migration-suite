"""
Unit tests for git_exporter.py
"""

import tempfile
import unittest
from backend.git_exporter import generate_git_ready_text, save_git_ready_runbook


class TestGitExporter(unittest.TestCase):

    def test_git_ready_formatting(self):
        text = generate_git_ready_text(
            rule_name="ADFind Recon Activity",
            severity="High",
            priority=7,
            mitre_tactic="Discovery",
            mitre_source="extracted from rule",
            mitre_uri="/All Stages/MITRE Tactics/Discovery",
            frequency_str="Matching 5 events in 10 Minutes",
            group_by=["deviceHostName", "destinationUserName"],
            kql_query="DeviceProcessEvents | where ProcessCommandLine has 'adfind.exe'",
            kql_validation={"passed": True, "coverage_pct": 100.0, "missing_required": []},
            spl_query="index=main CommandLine='*adfind.exe*'",
            spl_validation={"passed": True, "coverage_pct": 100.0, "missing_required": []},
            threat_analysis={
                "threat_summary": "Adversaries use adfind.exe to enumerate Active Directory.",
                "mitre_techniques": [{"technique_id": "T1087.002", "technique_name": "Domain Account"}],
            },
            mde_verdict="Partial / Custom Rule Required",
            mde_notes="Default MDE detects execution but does not alert on specific query arguments.",
            reviewer_name="Jane Doe (Sr Detection Eng)",
        )

        self.assertIn("RULE NAME: ADFind Recon Activity", text)
        self.assertIn("1. MICROSOFT DEFENDER (MDE) NATIVE COVERAGE ASSESSMENT [HUMAN REVIEW ONLY]", text)
        self.assertIn("VERDICT: Partial / Custom Rule Required", text)
        self.assertIn("Jane Doe (Sr Detection Eng)", text)
        self.assertIn("Trustworthiness: extracted from rule", text)
        self.assertIn("DeviceProcessEvents", text)

    def test_save_runbook_to_disk(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            res = save_git_ready_runbook("Test Rule 1", "Sample runbook content", output_dir=tmp_dir)
            self.assertEqual(res["filename"], "Test_Rule_1.txt")
            self.assertTrue(res["bytes_written"] > 0)


if __name__ == "__main__":
    unittest.main()

