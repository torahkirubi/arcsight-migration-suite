"""
test_telemetry_tuner_api.py - TDD Unit Tests for Telemetry Baselining & LLM Noise Diagnostics API

Requirements tested:
1. Authentication: POST /api/telemetry/tune requires a valid JWT bearer token, returning 401 if missing/invalid.
2. Standalone Execution: Accepts raw_kql and optional current_threshold (defaults to 1).
3. Telemetry Baselining: Mocks SentinelClient.execute_query returning baseline count & sample events,
   verifying original_threshold, suggested_threshold, and tuning_rationale in response.
4. LLM Noise Diagnostics: Mocks Gemini client in tuning pipeline, verifying structured noise_diagnostics
   (noise_source, affected_entities, mitigation_steps).
5. Clean Degradation: Verifies noise_diagnostics is None if Sentinel returns 0 events or if the LLM call fails.
"""

import json
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from backend.app import app
from backend.auth_vault import create_jwt_token
from backend.sentinel_client import SentinelClient

try:
    from fastapi.testclient import TestClient
except ImportError:
    class TestResponse:
        """Fallback TestResponse when fastapi is not installed in the test environment."""

        def __init__(self, status_code: int, data: dict):
            self.status_code = status_code
            self._data = data

        def json(self):
            return self._data if isinstance(self._data, dict) else {}

    class TestClient:
        """Fallback TestClient when fastapi.testclient is not installed in the test environment."""

        def __init__(self, app=None):
            self.app = app

        def _dispatch(self, method: str, url: str, json: dict = None, headers: dict = None, params: dict = None):
            if self.app is None:
                return TestResponse(404, {"detail": "Endpoint not found (app is None)"})

            routes = getattr(self.app, "routes", [])
            for route in routes:
                route_path = getattr(route, "path", None)
                route_methods = getattr(route, "methods", set())
                if route_path == url and method in route_methods:
                    endpoint = getattr(route, "endpoint", None)
                    if endpoint:
                        import asyncio
                        import inspect

                        sig = inspect.signature(endpoint)
                        kwargs = {}
                        for name, param in sig.parameters.items():
                            if name in ("payload", "body", "credentials", "login_data", "request", "req", "tune_request", "data"):
                                ann = param.annotation
                                if ann != inspect.Parameter.empty and callable(ann):
                                    try:
                                        kwargs[name] = ann(**(json or {}))
                                    except Exception:
                                        kwargs[name] = json
                                else:
                                    kwargs[name] = json
                            elif name in ("authorization", "token"):
                                auth_header = (headers or {}).get("Authorization") or (headers or {}).get("authorization")
                                kwargs[name] = auth_header
                            elif params and name in params:
                                kwargs[name] = params[name]

                        try:
                            if inspect.iscoroutinefunction(endpoint):
                                res = asyncio.run(endpoint(**kwargs))
                            else:
                                res = endpoint(**kwargs)
                            return TestResponse(200, res if isinstance(res, (dict, list)) else {})
                        except Exception as exc:
                            status_code = getattr(exc, "status_code", 500)
                            detail = getattr(exc, "detail", str(exc))
                            return TestResponse(status_code, {"detail": detail, "error": str(exc)})

            return TestResponse(404, {"detail": f"Route {url} not found"})

        def post(self, url: str, json: dict = None, headers: dict = None):
            return self._dispatch("POST", url, json=json, headers=headers)

        def get(self, url: str, headers: dict = None, params: dict = None):
            return self._dispatch("GET", url, headers=headers, params=params)


class TestTelemetryTunerAPI(unittest.TestCase):
    """Test suite for POST /api/telemetry/tune endpoint."""

    def setUp(self):
        self.client = TestClient(app)
        self.valid_token = create_jwt_token("admin")
        self.auth_headers = {"Authorization": f"Bearer {self.valid_token}"}

        self.sample_kql = (
            "SecurityEvent\n"
            "| where EventID == 4625\n"
            "| where AccountType != 'Machine'\n"
            "| summarize count() by TargetAccount, bin(TimeGenerated, 5m)"
        )

        self.sample_raw_records = [
            {
                "TimeGenerated": "2026-09-10T00:00:00Z",
                "TargetAccount": "svc-backup",
                "Computer": f"DC-PROD-{i:02d}.corp.internal",
                "EventID": 4625,
                "IpAddress": "10.0.4.15",
                "Activity": "Logon Failure",
            }
            for i in range(10)
        ]

        self.mock_sentinel_response = {
            "row_count": 200,
            "sample_records": self.sample_raw_records,
            "records": self.sample_raw_records,
            "events": self.sample_raw_records,
            "success": True,
        }

        self.mock_diagnostics_payload = {
            "noise_source": "Scheduled Backup Script",
            "affected_entities": [
                {"field": "Computer", "value": "DC-PROD-01.corp.internal"},
                {"field": "AccountName", "value": "svc-backup"},
                {"field": "IpAddress", "value": "10.0.4.15"},
            ],
            "mitigation_steps": [
                "Exclude TargetAccount == 'svc-backup' during 02:00-04:00 UTC maintenance windows",
                "Add filter: | where IpAddress != '10.0.4.15' for dedicated backup appliance",
            ],
        }

    # =========================================================================
    # 1. Authentication Requirement
    # =========================================================================

    def test_telemetry_tune_requires_authentication(self):
        """Assert that POST /api/telemetry/tune returns 401 Unauthorized without a valid JWT token."""
        # Case 1: Missing Authorization header
        resp_no_auth = self.client.post(
            "/api/telemetry/tune",
            json={"raw_kql": self.sample_kql, "current_threshold": 5, "llm_config": {"provider": "gemini", "model_name": "test-model", "custom_base_url": "https://llm.test/v1", "api_key": "test-key"}},
        )
        self.assertEqual(resp_no_auth.status_code, 401)

        # Case 2: Invalid Bearer token
        resp_bad_auth = self.client.post(
            "/api/telemetry/tune",
            json={"raw_kql": self.sample_kql, "current_threshold": 5, "llm_config": {"provider": "gemini", "model_name": "test-model", "custom_base_url": "https://llm.test/v1", "api_key": "test-key"}},
            headers={"Authorization": "Bearer invalid.malformed.token"},
        )
        self.assertEqual(resp_bad_auth.status_code, 401)

    # =========================================================================
    # 2. Standalone Execution & Telemetry Baselining
    # =========================================================================

    def test_telemetry_tune_standalone_execution_and_baselining(self):
        """Test POST /api/telemetry/tune accepts raw_kql and current_threshold, returning dynamic threshold calculations."""
        with patch.object(SentinelClient, "execute_query", create=True, return_value=self.mock_sentinel_response), \
             patch("backend.telemetry_tuner.get_llm_client", create=True, return_value=None):

            resp = self.client.post(
                "/api/telemetry/tune",
                json={"raw_kql": self.sample_kql, "current_threshold": 5, "llm_config": {"provider": "gemini", "model_name": "test-model", "custom_base_url": "https://llm.test/v1", "api_key": "test-key"}},
                headers=self.auth_headers,
            )

            self.assertEqual(resp.status_code, 200)
            data = resp.json()

            self.assertEqual(data.get("original_threshold"), 5)
            self.assertIn("suggested_threshold", data)
            self.assertGreater(data["suggested_threshold"], 5)
            self.assertIn("tuning_rationale", data)
            self.assertIn("200", data["tuning_rationale"])

    def test_telemetry_tune_default_current_threshold(self):
        """Assert current_threshold defaults to 1 when omitted from the request payload."""
        with patch.object(SentinelClient, "execute_query", create=True, return_value=self.mock_sentinel_response), \
             patch("backend.telemetry_tuner.get_llm_client", create=True, return_value=None):

            resp = self.client.post(
                "/api/telemetry/tune",
                json={"raw_kql": self.sample_kql},
                headers=self.auth_headers,
            )

            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertEqual(data.get("original_threshold"), 1)
            self.assertGreater(data.get("suggested_threshold", 0), 1)

    # =========================================================================
    # 3. LLM Noise Diagnostics
    # =========================================================================

    def test_telemetry_tune_llm_noise_diagnostics(self):
        """Mock Gemini client call and assert response returns structured noise_diagnostics."""
        mock_llm = MagicMock()
        mock_llm.complete = AsyncMock(return_value=json.dumps(self.mock_diagnostics_payload))

        with patch.object(SentinelClient, "execute_query", create=True, return_value=self.mock_sentinel_response), \
             patch("backend.telemetry_tuner.get_llm_client", create=True, return_value=mock_llm), \
             patch("backend.app.get_llm_client", return_value=mock_llm):

            resp = self.client.post(
                "/api/telemetry/tune",
                json={"raw_kql": self.sample_kql, "current_threshold": 5, "llm_config": {"provider": "gemini", "model_name": "test-model", "custom_base_url": "https://llm.test/v1", "api_key": "test-key"}},
                headers=self.auth_headers,
            )

            self.assertEqual(resp.status_code, 200)
            data = resp.json()

            self.assertIn("noise_diagnostics", data)
            diagnostics = data["noise_diagnostics"]
            self.assertIsInstance(diagnostics, dict)

            self.assertEqual(diagnostics.get("noise_source"), "Scheduled Backup Script")
            self.assertEqual(
                diagnostics.get("affected_entities"),
                [
                    {"field": "Computer", "value": "DC-PROD-01.corp.internal"},
                    {"field": "AccountName", "value": "svc-backup"},
                    {"field": "IpAddress", "value": "10.0.4.15"},
                ],
            )
            self.assertIn("mitigation_steps", diagnostics)
            self.assertIsInstance(diagnostics["mitigation_steps"], list)
            self.assertGreater(len(diagnostics["mitigation_steps"]), 0)

            # Assert auto-mitigated tuned_kql is present in response payload
            self.assertIn("tuned_kql", data)
            self.assertIsInstance(data["tuned_kql"], str)
            self.assertIn("!in", data["tuned_kql"])
            for entity in ["DC-PROD-01.corp.internal", "svc-backup", "10.0.4.15"]:
                self.assertIn(entity, data["tuned_kql"])
            summarize_idx = data["tuned_kql"].find("| summarize")
            exclusion_idx = data["tuned_kql"].find("!in")
            self.assertNotEqual(summarize_idx, -1)
            self.assertNotEqual(exclusion_idx, -1)
            self.assertLess(exclusion_idx, summarize_idx)

    # =========================================================================
    # 4. Clean Degradation
    # =========================================================================

    def test_telemetry_tune_clean_degradation_zero_events(self):
        """Assert that if Sentinel returns 0 events, baseline calculation succeeds and noise_diagnostics is None."""
        zero_sentinel_response = {
            "row_count": 0,
            "sample_records": [],
            "records": [],
            "events": [],
            "success": True,
        }

        with patch.object(SentinelClient, "execute_query", create=True, return_value=zero_sentinel_response):
            resp = self.client.post(
                "/api/telemetry/tune",
                json={"raw_kql": self.sample_kql, "current_threshold": 10},
                headers=self.auth_headers,
            )

            self.assertEqual(resp.status_code, 200)
            data = resp.json()

            self.assertEqual(data.get("original_threshold"), 10)
            self.assertEqual(data.get("suggested_threshold"), 10)
            self.assertIsNone(data.get("noise_diagnostics"))

    def test_telemetry_tune_clean_degradation_llm_failure(self):
        """Assert that if the LLM call fails, the endpoint returns baseline calculations gracefully with noise_diagnostics=None."""
        mock_failing_llm = MagicMock()
        mock_failing_llm.complete = AsyncMock(side_effect=Exception("Gemini API quota exceeded or connection timeout"))

        with patch.object(SentinelClient, "execute_query", create=True, return_value=self.mock_sentinel_response), \
             patch("backend.telemetry_tuner.get_llm_client", create=True, return_value=mock_failing_llm), \
             patch("backend.app.get_llm_client", return_value=mock_failing_llm):

            resp = self.client.post(
                "/api/telemetry/tune",
                json={"raw_kql": self.sample_kql, "current_threshold": 5},
                headers=self.auth_headers,
            )

            self.assertEqual(resp.status_code, 200)
            data = resp.json()

            self.assertEqual(data.get("original_threshold"), 5)
            self.assertGreater(data.get("suggested_threshold", 0), 5)
            self.assertIsNone(data.get("noise_diagnostics"))

    def test_diagnose_telemetry_noise_passes_max_tokens_8192(self):
        """Assert that diagnose_telemetry_noise explicitly requests max_tokens=8192 from LLM."""
        import asyncio
        from backend.app import diagnose_telemetry_noise

        mock_llm = MagicMock()
        mock_llm.complete = AsyncMock(return_value='{"noise_source": "Scanner", "affected_entities": ["h1"], "mitigation_steps": ["step1"]}')

        records = [{"Computer": "HOST-1", "EventID": 4625}]
        res = asyncio.run(diagnose_telemetry_noise("SecurityEvent", records, mock_llm))

        self.assertIsNotNone(res)
        mock_llm.complete.assert_called_once()
        call_kwargs = mock_llm.complete.call_args[1]
        self.assertEqual(call_kwargs.get("max_tokens"), 8192)

    def test_diagnose_telemetry_noise_markdown_fence_recovery(self):
        """Assert that diagnose_telemetry_noise cleanly strips markdown code fences."""
        import asyncio
        from backend.app import diagnose_telemetry_noise

        fenced_json = """```json
{
  "noise_source": "Scheduled Backup Script",
  "affected_entities": [{"field": "Computer", "value": "SRV-BACKUP-01"}],
  "mitigation_steps": ["| where Computer != 'SRV-BACKUP-01'"]
}
```"""
        mock_llm = MagicMock()
        mock_llm.complete = AsyncMock(return_value=fenced_json)

        records = [{"Computer": "SRV-BACKUP-01", "EventID": 4625}]
        res = asyncio.run(diagnose_telemetry_noise("SecurityEvent", records, mock_llm))

        self.assertIsNotNone(res)
        self.assertEqual(res["noise_source"], "Scheduled Backup Script")
        self.assertEqual(res["affected_entities"], [{"field": "Computer", "value": "SRV-BACKUP-01"}])
        self.assertEqual(res["mitigation_steps"], ["| where Computer != 'SRV-BACKUP-01'"])

    def test_diagnose_telemetry_noise_aliased_keys_recovery(self):
        """Assert that diagnose_telemetry_noise defensively handles root_cause, noise_entities, and mitigated_kql aliases."""
        import asyncio
        from backend.app import diagnose_telemetry_noise

        aliased_json = json.dumps({
            "root_cause": "Nessus Vulnerability Scan",
            "noise_entities": [
                {"field": "IpAddress", "value": "192.168.1.100"},
                {"field": "IpAddress", "value": "192.168.1.101"},
            ],
            "mitigated_kql": "| where IpAddress !in ('192.168.1.100', '192.168.1.101')"
        })
        mock_llm = MagicMock()
        mock_llm.complete = AsyncMock(return_value=aliased_json)

        records = [{"IpAddress": "192.168.1.100"}]
        res = asyncio.run(diagnose_telemetry_noise("CommonSecurityLog", records, mock_llm))

        self.assertIsNotNone(res)
        self.assertEqual(res["noise_source"], "Nessus Vulnerability Scan")
        self.assertEqual(res["affected_entities"], [
            {"field": "IpAddress", "value": "192.168.1.100"},
            {"field": "IpAddress", "value": "192.168.1.101"},
        ])
        self.assertEqual(res["mitigation_steps"], ["| where IpAddress !in ('192.168.1.100', '192.168.1.101')"])

    def test_noise_diagnostics_system_prompt_strict_schema_field_constraint(self):
        """Assert that NOISE_DIAGNOSTICS_SYSTEM_PROMPT contains the strict schema field constraint."""
        from backend.app import NOISE_DIAGNOSTICS_SYSTEM_PROMPT
        self.assertIn('NEVER use generic placeholder field names such as "Object", "Entity", or "Target"', NOISE_DIAGNOSTICS_SYSTEM_PROMPT)
        self.assertIn("You must ONLY use real column names present in the input query and sample records", NOISE_DIAGNOSTICS_SYSTEM_PROMPT)
        self.assertIn("For hostnames or machines, ALWAYS use: Computer", NOISE_DIAGNOSTICS_SYSTEM_PROMPT)
        self.assertIn("For usernames, ALWAYS use: AccountName", NOISE_DIAGNOSTICS_SYSTEM_PROMPT)

    def test_diagnose_telemetry_noise_normalizes_labeled_entity_strings(self):
        """Labeled string entities are normalized before exclusion generation."""
        import asyncio
        from backend.app import diagnose_telemetry_noise

        mock_llm = MagicMock()
        mock_llm.complete = AsyncMock(return_value=json.dumps({
            "noise_source": "Scanner",
            "affected_entities": [
                "AccountName: svc-scanner",
                "Computer: DC-01.corp.local",
            ],
            "mitigation_steps": ["Exclude scanner noise"],
        }))

        result = asyncio.run(
            diagnose_telemetry_noise(
                "SecurityEvents_CL | summarize count() by Computer, AccountName",
                [{"Computer": "DC-01.corp.local", "AccountName": "svc-scanner"}],
                mock_llm,
            )
        )
        self.assertEqual(result["affected_entities"], [
            {"field": "AccountName", "value": "svc-scanner"},
            {"field": "Computer", "value": "DC-01.corp.local"},
        ])

    def test_tune_telemetry_unpacks_real_records_and_applies_exclusions_without_generic_object(self):
        """Assert that tune_telemetry unpacks real records from Sentinel and applies exclusions without 'Object'."""
        mock_sentinel_res = {
            "row_count": 25,
            "records": [
                {"TimeGenerated": "2026-09-10T12:00:00Z", "Computer": "CORP-WS-01", "AccountName": "svc-backup", "EventID": 4625}
            ]
        }
        mock_llm = MagicMock()
        mock_llm.complete = AsyncMock(return_value=json.dumps({
            "noise_source": "Automated Backup Account",
            "affected_entities": [{"field": "AccountName", "value": "svc-backup"}],
            "mitigation_steps": ["Exclude svc-backup from alerts"]
        }))

        with patch.object(SentinelClient, "execute_query", create=True, return_value=mock_sentinel_res), \
             patch("backend.app.get_llm_client", return_value=mock_llm):

            resp = self.client.post(
                "/api/telemetry/tune",
                json={"raw_kql": "SecurityEvent | where EventID == 4625 | summarize count() by AccountName", "current_threshold": 5, "llm_config": {"provider": "gemini", "model_name": "test-model", "custom_base_url": "https://llm.test/v1", "api_key": "test-key"}},
                headers=self.auth_headers,
            )

            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            tuned_kql = data.get("tuned_kql")
            self.assertIsNotNone(tuned_kql)
            self.assertNotIn("where Object", tuned_kql)
            self.assertIn("where AccountName !in ('svc-backup')", tuned_kql)

    def test_sentinel_client_execute_query_preserves_real_records_from_tables(self):
        """Assert that Sentinel execute_query unpacks tables before synthetic fallback."""
        client = SentinelClient("t", "c", "s", "w")
        mock_kql_res = {
            "row_count": 1,
            "tables": [{
                "name": "PrimaryResult",
                "columns": [{"name": "TimeGenerated"}, {"name": "Computer"}, {"name": "AccountName"}],
                "rows": [["2026-09-10T12:00:00Z", "DC-01", "admin-scanner"]]
            }]
        }
        with patch.object(client, "execute_kql_query", return_value=mock_kql_res):
            res = client.execute_query("SecurityEvent | take 1")
            self.assertEqual(len(res["sample_records"]), 1)
            self.assertEqual(res["sample_records"][0]["Computer"], "DC-01")
            self.assertEqual(res["sample_records"][0]["AccountName"], "admin-scanner")

    def test_execute_kql_query_no_credentials_returns_empty_sample_records(self):
        """Assert that execute_kql_query returns empty sample_records (not HOST-i mocks) when no credentials are configured.

        Root cause: The fallback block in execute_kql_query populates sample_records with synthetic
        HOST-{i} data, which propagates all the way to the LLM prompt, preventing real diagnosis.
        When no Sentinel credentials are configured, sample_records should be [] so that the tuning
        pipeline can correctly detect that no real data is available.
        """
        client = SentinelClient("", "", "", "")
        result = client.execute_kql_query("SecurityEvent | take 10")
        self.assertIsInstance(result, dict)
        sample_records = result.get("sample_records", [])
        # Must not return synthetic HOST-{i} mock data when no real credentials are configured
        for rec in sample_records:
            if isinstance(rec, dict):
                computer = rec.get("Computer", "")
                self.assertFalse(
                    computer.startswith("HOST-"),
                    f"execute_kql_query must not return synthetic HOST-{{i}} mock records; got: {rec}"
                )

    def test_execute_kql_query_with_tables_returns_rich_records_with_all_fields(self):
        """Assert execute_kql_query unpacks a tables response with Computer, AccountName, ProcessName, CommandLine.

        The Azure Log Analytics API returns: {"tables": [{"columns": [...], "rows": [...]}]}
        execute_kql_query must unpack this structure into sample_records list of dicts.
        We test this by patching the internal HTTP call path via execute_kql_query itself,
        injecting a realistic API response shape at the sentinel_client level.
        """
        client = SentinelClient("tenant", "client", "secret", "workspace")
        # Simulate the parsed JSON body the Azure LA API returns
        real_api_tables_response = {
            "success": True,
            "row_count": 2,
            "tables": [{
                "name": "PrimaryResult",
                "columns": [
                    {"name": "TimeGenerated", "type": "datetime"},
                    {"name": "Computer", "type": "string"},
                    {"name": "AccountName", "type": "string"},
                    {"name": "ProcessName", "type": "string"},
                    {"name": "CommandLine", "type": "string"},
                    {"name": "EventID", "type": "int"},
                ],
                "rows": [
                    ["2026-09-11T00:00:00Z", "SRV-01.corp.local", "svc-scanner", "powershell.exe",
                     "powershell -nop -enc <base64>", 4625],
                    ["2026-09-11T00:01:00Z", "SRV-02.corp.local", "svc-backup", "nssm.exe",
                     "nssm start BackupService", 4624],
                ]
            }]
        }
        # execute_query calls execute_kql_query internally; mock execute_kql_query to return tables structure
        with patch.object(client, "execute_kql_query", return_value=real_api_tables_response):
            result = client.execute_query("SecurityEvent | take 20")

        records = result["sample_records"]
        self.assertEqual(len(records), 2)
        # First row: SRV-01 with svc-scanner
        self.assertEqual(records[0]["Computer"], "SRV-01.corp.local")
        self.assertEqual(records[0]["AccountName"], "svc-scanner")
        self.assertEqual(records[0]["ProcessName"], "powershell.exe")
        self.assertEqual(records[0]["CommandLine"], "powershell -nop -enc <base64>")
        self.assertEqual(records[0]["EventID"], 4625)
        # Second row: SRV-02 with svc-backup
        self.assertEqual(records[1]["Computer"], "SRV-02.corp.local")
        self.assertEqual(records[1]["AccountName"], "svc-backup")
        self.assertNotIn("HOST-", records[0].get("Computer", ""))
        self.assertNotIn("HOST-", records[1].get("Computer", ""))

    def test_full_pipeline_llm_prompt_receives_rich_records_not_host_mocks(self):
        """Assert that the LLM diagnose_telemetry_noise call receives records with AccountName, ProcessName, CommandLine.

        This test validates that when Sentinel returns rich records (Computer, AccountName, ProcessName,
        CommandLine), those fields survive intact all the way to the diagnose_telemetry_noise call —
        not the synthetic HOST-{i} mock records.
        """
        import asyncio
        rich_sentinel_records = [
            {
                "TimeGenerated": "2026-09-11T00:00:00Z",
                "Computer": "SRV-01.corp.local",
                "AccountName": "svc-scanner",
                "ProcessName": "powershell.exe",
                "CommandLine": "powershell -nop -enc <base64>",
                "EventID": 4625,
            }
        ]
        mock_sentinel_res = {
            "row_count": 50,
            "sample_records": rich_sentinel_records,
        }
        captured_prompt_records = []

        async def mock_diagnose(raw_kql, sample_records, llm_client):
            captured_prompt_records.extend(sample_records)
            return {
                "noise_source": "Automated Scanner",
                "affected_entities": ["svc-scanner"],
                "mitigation_steps": ["Exclude svc-scanner"]
            }

        mock_llm = MagicMock()
        mock_llm.complete = AsyncMock(return_value=json.dumps({
            "noise_source": "Automated Scanner",
            "affected_entities": ["svc-scanner"],
            "mitigation_steps": ["Exclude svc-scanner"]
        }))

        with patch.object(SentinelClient, "execute_query", create=True, return_value=mock_sentinel_res), \
             patch("backend.app.get_llm_client", return_value=mock_llm), \
             patch("backend.app.diagnose_telemetry_noise", side_effect=mock_diagnose):

            resp = self.client.post(
                "/api/telemetry/tune",
                json={"raw_kql": "SecurityEvent | where EventID == 4625 | summarize count() by AccountName, Computer", "current_threshold": 10, "llm_config": {"provider": "gemini", "model_name": "test-model", "custom_base_url": "https://llm.test/v1", "api_key": "test-key"}},
                headers=self.auth_headers,
            )

        self.assertEqual(resp.status_code, 200)
        # Verify the records that reached the LLM have real fields — not HOST-{i} mocks
        self.assertGreater(len(captured_prompt_records), 0, "No records were forwarded to diagnose_telemetry_noise")
        first_rec = captured_prompt_records[0]
        self.assertIn("AccountName", first_rec, "AccountName must be present in records passed to LLM")
        self.assertIn("ProcessName", first_rec, "ProcessName must be present in records passed to LLM")
        self.assertIn("CommandLine", first_rec, "CommandLine must be present in records passed to LLM")
        self.assertNotEqual(first_rec.get("Computer", ""), "HOST-0",
                            "Synthetic HOST-0 mock must not reach the LLM prompt")

    def test_apply_exclusions_targets_commandline_when_explicitly_specified(self):
        """Assert apply_exclusions targets CommandLine when target_field is explicitly set."""
        from backend.telemetry_tuner import apply_exclusions
        raw_kql = (
            "SecurityEvent\n"
            "| where EventID == 4688\n"
            "| summarize count() by CommandLine, Computer"
        )
        tuned = apply_exclusions(raw_kql, ["powershell -nop -enc <base64>", "nssm start BackupService"],
                                 target_field="CommandLine")
        self.assertIn("CommandLine !in (", tuned)
        self.assertNotIn("Object", tuned)
        self.assertNotIn("Computer !in", tuned)
        # Negative logic retention
        self.assertIn("!in", tuned)


    def test_tune_telemetry_with_dictionary_entities_generates_multi_column_exclusions(self):
        """Assert that /api/telemetry/tune handles structured dictionary entities from LLM and generates multi-column exclusions."""
        mock_sentinel_res = {
            "row_count": 100,
            "sample_records": [
                {
                    "TimeGenerated": "2026-09-11T00:00:00Z",
                    "Computer": "SRV-01.corp.local",
                    "AccountName": "svc-scanner",
                    "CommandLine": "net.exe user /domain",
                }
            ],
        }
        structured_diagnostics = {
            "noise_source": "Scheduled Scanner Service",
            "affected_entities": [
                {"AccountName": "svc-scanner"},
                {"AccountName": "svc-backup"},
                {"Computer": "SRV-01.corp.local"},
                {"CommandLine": "net.exe user /domain"},
            ],
            "mitigation_steps": ["Exclude scanner accounts and noisy hosts"],
        }
        mock_llm = MagicMock()
        mock_llm.complete = AsyncMock(return_value=json.dumps(structured_diagnostics))

        raw_query = (
            "SecurityEvents_CL\n"
            "| where TimeGenerated > ago(7d)\n"
            "| summarize AlertCount=count() by Computer, AccountName, ProcessName, CommandLine\n"
            "| order by AlertCount desc"
        )

        with patch.object(SentinelClient, "execute_query", create=True, return_value=mock_sentinel_res), \
             patch("backend.app.get_llm_client", return_value=mock_llm):

            resp = self.client.post(
                "/api/telemetry/tune",
                json={"raw_kql": raw_query, "current_threshold": 10, "llm_config": {"provider": "gemini", "model_name": "test-model", "custom_base_url": "https://llm.test/v1", "api_key": "test-key"}},
                headers=self.auth_headers,
            )

        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        tuned_kql = data.get("tuned_kql")
        self.assertIsNotNone(tuned_kql)

        # Assert multi-column clauses
        self.assertIn("| where AccountName !in ('svc-scanner', 'svc-backup')", tuned_kql)
        self.assertIn("| where Computer !in ('SRV-01.corp.local')", tuned_kql)
        self.assertIn("| where CommandLine !in ('net.exe user /domain')", tuned_kql)

        # Assert no raw dictionary stringification
        self.assertNotIn("{'AccountName'", tuned_kql)
        self.assertNotIn("Object", tuned_kql)

        # Negative logic retention
        self.assertIn("!in", tuned_kql)


if __name__ == "__main__":
    unittest.main()
