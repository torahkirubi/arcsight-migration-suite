import unittest

from backend.batch_migration_compiler import compile_rules
from backend.schemas.exclusion_ir import (
    CompoundCondition,
    CompoundExclusion,
    RuleTuningAnalysis,
    SingleFieldExclusion,
)
from backend.telemetry_tuner import KQLQueryCompiler


class TestCompilerIR(unittest.TestCase):
    def test_compiles_allowlisted_single_field_exclusions(self):
        analysis = RuleTuningAnalysis(
            noise_summary="Scanner service",
            recommended_threshold=10,
            exclusions=[
                SingleFieldExclusion(
                    field="AccountName",
                    values=["svc-scanner", "svc'backup"],
                ),
                SingleFieldExclusion(field="Computer", values=["DC-01"]),
            ],
        )
        query = KQLQueryCompiler("SecurityEvents_CL | summarize count()").render(analysis)
        self.assertIn("| where AccountName !in ('svc-scanner', 'svc\\'backup')", query)
        self.assertIn("| where Computer !in ('DC-01')", query)

    def test_compiles_compound_conditions(self):
        analysis = RuleTuningAnalysis(
            noise_summary="Process noise",
            recommended_threshold=3,
            exclusions=[
                CompoundExclusion(
                    conditions=[
                        CompoundCondition(field="Computer", operator="==", value="HOST-1"),
                        CompoundCondition(field="CommandLine", operator="contains", value="net.exe"),
                    ]
                )
            ],
        )
        query = KQLQueryCompiler("SecurityEvent | summarize count()").render(analysis)
        self.assertIn("| where not (Computer == 'HOST-1' and CommandLine has 'net.exe')", query)

    def test_batch_runner_reports_schema_errors(self):
        report = compile_rules([
            {
                "id": "valid",
                "raw_kql": "SigninLogs | count",
                "analysis": {
                    "noise_summary": "IP noise",
                    "recommended_threshold": 2,
                    "exclusions": [
                        {"type": "single_field", "field": "IPAddress", "values": ["10.0.0.1"]}
                    ],
                },
            },
            {"id": "invalid", "raw_kql": "SigninLogs | count", "analysis": {}},
        ])
        self.assertEqual(report["passed"], 1)
        self.assertEqual(report["schema_errors"], 1)
