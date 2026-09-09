"""
test_deep_mode.py - Unit tests for Deep Mode autonomous Splunk testing & self-correction loop
"""

import asyncio
import unittest
from unittest.mock import patch, AsyncMock, MagicMock

from backend.app import (
    execute_translate_direct,
    stream_translate_direct,
    TranslateDirectRequest,
    LLMConfigPayload,
    make_json_serializable,
)
from backend.direct_translate_prompts import sanitize_query, extract_queries_from_response
from backend.splunk_client import SplunkTestClient


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

VALID_LLM_OUTPUT = """```kql
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
```"""

CORRECTED_LLM_OUTPUT = """```kql
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
| stats count by dest, user, _time
| search count >= 5
```"""


class TestDeepModeAutonomousLoop(unittest.TestCase):

    @patch("backend.app.get_llm_client")
    @patch("backend.app.SplunkTestClient")
    def test_deep_mode_disabled_single_shot(self, mock_splunk_cls, mock_get_llm):
        """When deep_mode is False, run standard single-shot translation."""
        mock_llm = MagicMock()
        mock_llm.complete = AsyncMock(return_value=VALID_LLM_OUTPUT)
        mock_get_llm.return_value = mock_llm

        mock_splunk = MagicMock()
        mock_splunk.test_connection = AsyncMock(return_value={"status": "disconnected"})
        mock_splunk_cls.return_value = mock_splunk

        req = TranslateDirectRequest(
            raw_text=SAMPLE_ARCSIGHT_RULE,
            llm_config=LLMConfigPayload(provider="lm_studio"),
            deep_mode=False,
        )
        res = asyncio.run(execute_translate_direct(req))

        self.assertTrue(res["success"])
        self.assertFalse(res["deep_mode"])
        self.assertEqual(mock_llm.complete.call_count, 1)

    @patch("backend.app.get_llm_client")
    @patch("backend.app.SplunkTestClient")
    def test_deep_mode_success_attempt_1(self, mock_splunk_cls, mock_get_llm):
        """When deep_mode is True and Splunk returns 200 OK on attempt 1, break immediately."""
        mock_llm = MagicMock()
        mock_llm.complete = AsyncMock(return_value=VALID_LLM_OUTPUT)
        mock_get_llm.return_value = mock_llm

        mock_splunk = MagicMock()
        mock_splunk.execute_oneshot_search = AsyncMock(return_value={"success": True, "hit_count": 5})
        mock_splunk_cls.return_value = mock_splunk

        req = TranslateDirectRequest(
            raw_text=SAMPLE_ARCSIGHT_RULE,
            llm_config=LLMConfigPayload(provider="lm_studio"),
            deep_mode=True,
        )
        res = asyncio.run(execute_translate_direct(req))

        self.assertTrue(res["success"])
        self.assertTrue(res["deep_mode"])
        self.assertTrue(res["deep_mode_passed"])
        self.assertFalse(res["deep_mode_failed"])
        self.assertEqual(res["deep_mode_attempts"], 1)
        self.assertEqual(mock_llm.complete.call_count, 1)
        self.assertIn("Deep Mode: SPL autonomously validated", " ".join(res["validation"]["spl"]["notes"]))

    @patch("backend.app.asyncio.sleep", new_callable=AsyncMock)
    @patch("backend.app.get_llm_client")
    @patch("backend.app.SplunkTestClient")
    def test_deep_mode_self_corrects_on_error(self, mock_splunk_cls, mock_get_llm, mock_sleep):
        """When attempt 1 fails Splunk validation, error is injected into prompt and attempt 2 succeeds."""
        mock_llm = MagicMock()
        prompts_received = []

        async def fake_complete(prompt, system_prompt, temperature, *args, **kwargs):
            prompts_received.append((prompt, temperature))
            if len(prompts_received) == 1:
                return VALID_LLM_OUTPUT
            return CORRECTED_LLM_OUTPUT

        mock_llm.complete = AsyncMock(side_effect=fake_complete)
        mock_get_llm.return_value = mock_llm

        mock_splunk = MagicMock()
        # Attempt 1: SearchParser failure; Attempt 2: Valid
        mock_splunk.execute_oneshot_search = AsyncMock(side_effect=[
            {"success": False, "error": "SearchParser failure: Unknown search command 'stats_count'"},
            {"success": True, "hit_count": 2},
        ])
        mock_splunk_cls.return_value = mock_splunk

        req = TranslateDirectRequest(
            raw_text=SAMPLE_ARCSIGHT_RULE,
            llm_config=LLMConfigPayload(provider="lm_studio"),
            deep_mode=True,
        )
        res = asyncio.run(execute_translate_direct(req))

        self.assertTrue(res["success"])
        self.assertTrue(res["deep_mode"])
        self.assertTrue(res["deep_mode_passed"])
        self.assertFalse(res["deep_mode_failed"])
        self.assertEqual(res["deep_mode_attempts"], 2)
        self.assertEqual(len(prompts_received), 2)

        # Check that rate limit cooldown sleep was called once with 3 seconds
        mock_sleep.assert_awaited_once_with(3)

        # Check attempt 1 vs attempt 2 temperature
        self.assertEqual(prompts_received[0][1], 0.1)
        self.assertEqual(prompts_received[1][1], 0.2)

        # Verify error injection prompt in attempt 2
        retry_prompt = prompts_received[1][0]
        self.assertIn("Your previous attempt failed validation with this Splunk error:", retry_prompt)
        self.assertIn("SearchParser failure: Unknown search command 'stats_count'", retry_prompt)
        self.assertIn("Analyze the syntax failure and rewrite the SPL query.", retry_prompt)

    @patch("backend.app.asyncio.sleep", new_callable=AsyncMock)
    @patch("backend.app.get_llm_client")
    @patch("backend.app.SplunkTestClient")
    def test_deep_mode_max_retries_exhausted(self, mock_splunk_cls, mock_get_llm, mock_sleep):
        """When 3 attempts all fail, terminates gracefully at 3 attempts with failure warning."""
        mock_llm = MagicMock()
        mock_llm.complete = AsyncMock(return_value=VALID_LLM_OUTPUT)
        mock_get_llm.return_value = mock_llm

        mock_splunk = MagicMock()
        mock_splunk.execute_oneshot_search = AsyncMock(return_value={
            "success": False,
            "error": "Syntax error at position 42",
        })
        mock_splunk_cls.return_value = mock_splunk

        req = TranslateDirectRequest(
            raw_text=SAMPLE_ARCSIGHT_RULE,
            llm_config=LLMConfigPayload(provider="lm_studio"),
            deep_mode=True,
        )
        res = asyncio.run(execute_translate_direct(req))

        self.assertTrue(res["success"])
        self.assertTrue(res["deep_mode"])
        self.assertFalse(res["deep_mode_passed"])
        self.assertTrue(res["deep_mode_failed"])
        self.assertEqual(res["deep_mode_attempts"], 3)
        self.assertEqual(mock_llm.complete.call_count, 3)
        # Sleep called twice: before attempt 2 and before attempt 3
        self.assertEqual(mock_sleep.await_count, 2)
        mock_sleep.assert_awaited_with(3)
        self.assertIn("Deep Mode Warning: Splunk validation failed after 3 attempt(s)", " ".join(res["validation"]["spl"]["notes"]))

    @patch("backend.app.get_llm_client")
    @patch("backend.app.SplunkTestClient")
    def test_deep_mode_splunk_unreachable_safe_fallback(self, mock_splunk_cls, mock_get_llm):
        """When Splunk is unreachable, backend does not crash and falls back safely without looping retries."""
        mock_llm = MagicMock()
        mock_llm.complete = AsyncMock(return_value=VALID_LLM_OUTPUT)
        mock_get_llm.return_value = mock_llm

        mock_splunk = MagicMock()
        mock_splunk.execute_oneshot_search = AsyncMock(return_value={
            "success": False,
            "error": "ConnectError: [Errno 111] Connection refused",
        })
        mock_splunk_cls.return_value = mock_splunk

        req = TranslateDirectRequest(
            raw_text=SAMPLE_ARCSIGHT_RULE,
            llm_config=LLMConfigPayload(provider="lm_studio"),
            deep_mode=True,
        )
        # Must never raise an unhandled exception
        res = asyncio.run(execute_translate_direct(req))

        self.assertTrue(res["success"])
        self.assertTrue(res["deep_mode"])
        self.assertFalse(res["deep_mode_passed"])
        self.assertEqual(res["deep_mode_attempts"], 1)  # Does not fruitlessly spin retries on connection failure
        self.assertEqual(mock_llm.complete.call_count, 1)
        self.assertIn("Splunk service unreachable", " ".join(res["validation"]["spl"]["notes"]))

    @patch("backend.app.get_llm_client")
    @patch("backend.app.SplunkTestClient")
    def test_stream_translate_direct_success(self, mock_splunk_cls, mock_get_llm):
        """Verify SSE streaming yields status chunks and final complete result."""
        import json
        mock_llm = MagicMock()
        mock_llm.complete = AsyncMock(return_value=VALID_LLM_OUTPUT)
        mock_get_llm.return_value = mock_llm

        mock_splunk = MagicMock()
        mock_splunk.execute_oneshot_search = AsyncMock(return_value={"success": True, "hit_count": 3})
        mock_splunk_cls.return_value = mock_splunk

        req = TranslateDirectRequest(
            raw_text=SAMPLE_ARCSIGHT_RULE,
            llm_config=LLMConfigPayload(provider="lm_studio"),
            deep_mode=True,
        )

        async def run_stream():
            events = []
            async for chunk in stream_translate_direct(req):
                # parse data: line
                for line in chunk.strip().split("\n"):
                    if line.startswith("data: "):
                        events.append(json.loads(line[6:]))
            return events

        events = asyncio.run(run_stream())
        self.assertTrue(len(events) >= 4)

        statuses = [e.get("status") for e in events if "status" in e]
        self.assertTrue(any("Drafting initial SPL..." in s for s in statuses))
        self.assertTrue(any("Testing against Splunk (Attempt 1)..." in s for s in statuses))
        self.assertTrue(any("Splunk validation PASSED on attempt 1" in s for s in statuses))

        # Check final event
        final_event = events[-1]
        self.assertEqual(final_event.get("type"), "result")
        self.assertEqual(final_event.get("status"), "complete")
        self.assertIn("result", final_event)
        self.assertTrue(final_event["result"]["deep_mode_passed"])
        self.assertTrue(len(final_event["result"]["kql_query"]) > 10)
        self.assertTrue(len(final_event["result"]["spl_query"]) > 10)

    @patch("backend.app.asyncio.sleep", new_callable=AsyncMock)
    @patch("backend.app.get_llm_client")
    @patch("backend.app.SplunkTestClient")
    def test_stream_translate_direct_retry_flow(self, mock_splunk_cls, mock_get_llm, mock_sleep):
        """Verify SSE streaming streams retry status on parser error and then succeeds."""
        import json
        mock_llm = MagicMock()
        mock_llm.complete = AsyncMock(side_effect=[VALID_LLM_OUTPUT, CORRECTED_LLM_OUTPUT])
        mock_get_llm.return_value = mock_llm

        mock_splunk = MagicMock()
        mock_splunk.execute_oneshot_search = AsyncMock(side_effect=[
            {"success": False, "error": "SearchParser failure: Unknown term"},
            {"success": True, "hit_count": 1},
        ])
        mock_splunk_cls.return_value = mock_splunk

        req = TranslateDirectRequest(
            raw_text=SAMPLE_ARCSIGHT_RULE,
            llm_config=LLMConfigPayload(provider="lm_studio"),
            deep_mode=True,
        )

        async def run_stream():
            events = []
            async for chunk in stream_translate_direct(req):
                for line in chunk.strip().split("\n"):
                    if line.startswith("data: "):
                        events.append(json.loads(line[6:]))
            return events

        events = asyncio.run(run_stream())
        statuses = [e.get("status") for e in events if "status" in e]
        self.assertTrue(any("Drafting initial SPL..." in s for s in statuses))
        self.assertTrue(any("Testing against Splunk (Attempt 1)..." in s for s in statuses))
        self.assertTrue(any("Parser failed, rewriting..." in s for s in statuses))
        self.assertTrue(any("Testing against Splunk (Attempt 2)..." in s for s in statuses))
        self.assertTrue(any("Splunk validation PASSED on attempt 2" in s for s in statuses))

        final_event = events[-1]
        self.assertEqual(final_event.get("status"), "complete")
        self.assertEqual(final_event["result"]["deep_mode_attempts"], 2)

    def test_sanitize_query_edge_cases(self):
        """Verify sanitize_query strips various markdown fence patterns without mangling Splunk macros."""
        cases = [
            ("```spl\nindex=main | stats count\n```", "index=main | stats count"),
            ("```spl\nindex=main | stats count", "index=main | stats count"),
            ("```spl\n```spl\nindex=main (process=\"*cmd.exe*\")\n```\n```", "index=main (process=\"*cmd.exe*\")"),
            ("```spl index=main sourcetype=access | stats count ```", "index=main sourcetype=access | stats count"),
            ("index=main | head 10\n```", "index=main | head 10"),
            ("```SPL\nindex=main | stats count\n```", "index=main | stats count"),
            ("```kql\nDeviceProcessEvents | where 1==1\n```", "DeviceProcessEvents | where 1==1"),
            ("```spl\n`drop_dm_object_name(\"All_Traffic\")` | stats count\n```", "`drop_dm_object_name(\"All_Traffic\")` | stats count"),
            ("`index=main | stats count`", "index=main | stats count"),
        ]
        for input_text, expected in cases:
            cleaned = sanitize_query(input_text)
            self.assertEqual(cleaned, expected, f"Failed for input: {repr(input_text)}")

    @patch("backend.app.get_llm_client")
    @patch("backend.app.SplunkTestClient")
    def test_deep_mode_spl_with_tickmarks_sanitized_before_splunk(self, mock_splunk_cls, mock_get_llm):
        """Ensure spl_query is completely raw and markdown-free before being passed into Splunk REST client."""
        # Simulated LLM output wrapped in messy markdown fences
        messy_llm_output = (
            "Here is the KQL:\n```kql\nDeviceProcessEvents | where FileName == 'cmd.exe'\n```\n\n"
            "And here is the SPL:\n```spl\n```spl\nindex=main (process=\"*cmd.exe*\") | stats count\n```\n```"
        )
        mock_llm = MagicMock()
        mock_llm.complete = AsyncMock(return_value=messy_llm_output)
        mock_get_llm.return_value = mock_llm

        splunk_query_received = []

        async def fake_oneshot(spl_query, *args, **kwargs):
            splunk_query_received.append(spl_query)
            return {"success": True, "hit_count": 1}

        mock_splunk = MagicMock()
        mock_splunk.execute_oneshot_search = AsyncMock(side_effect=fake_oneshot)
        mock_splunk_cls.return_value = mock_splunk

        req = TranslateDirectRequest(
            raw_text=SAMPLE_ARCSIGHT_RULE,
            llm_config=LLMConfigPayload(provider="lm_studio"),
            deep_mode=True,
        )
        res = asyncio.run(execute_translate_direct(req))

        self.assertTrue(res["success"])
        self.assertEqual(len(splunk_query_received), 1)

        # 1. Verify query sent to Splunk has no ``` or ```spl
        sent_query = splunk_query_received[0]
        self.assertNotIn("```", sent_query)
        self.assertNotIn("```spl", sent_query)
        self.assertEqual(sent_query, 'index=main (process="*cmd.exe*") | stats count')

        # 2. Verify final payload queries are clean raw strings
        self.assertNotIn("```", res["spl_query"])
        self.assertEqual(res["spl_query"], 'index=main (process="*cmd.exe*") | stats count')
        self.assertNotIn("```", res["kql_query"])
        self.assertEqual(res["kql_query"], "DeviceProcessEvents | where FileName == 'cmd.exe'")

    @patch("backend.app.asyncio.sleep", new_callable=AsyncMock)
    @patch("backend.app.get_llm_client")
    @patch("backend.app.SplunkTestClient")
    def test_deep_mode_preserves_kql_when_attempt_2_returns_only_spl(self, mock_splunk_cls, mock_get_llm, mock_sleep):
        """When attempt 2 rewrite returns only SPL (without re-emitting KQL), KQL from attempt 1 is preserved."""
        attempt1_output = VALID_LLM_OUTPUT
        attempt2_only_spl = "```spl\nindex=main (process=\"*cmd.exe*\") | stats count\n```"

        mock_llm = MagicMock()
        mock_llm.complete = AsyncMock(side_effect=[attempt1_output, attempt2_only_spl])
        mock_get_llm.return_value = mock_llm

        mock_splunk = MagicMock()
        mock_splunk.execute_oneshot_search = AsyncMock(side_effect=[
            {"success": False, "error": "SearchParser failure: tickmarks error"},
            {"success": True, "hit_count": 2},
        ])
        mock_splunk_cls.return_value = mock_splunk

        req = TranslateDirectRequest(
            raw_text=SAMPLE_ARCSIGHT_RULE,
            llm_config=LLMConfigPayload(provider="lm_studio"),
            deep_mode=True,
        )
        res = asyncio.run(execute_translate_direct(req))

        self.assertTrue(res["success"])
        self.assertTrue(res["deep_mode_passed"])
        self.assertEqual(res["deep_mode_attempts"], 2)

        # KQL must NOT be empty — preserved from attempt 1
        self.assertIn("DeviceProcessEvents", res["kql_query"])
        self.assertNotIn("```", res["kql_query"])

        # SPL must be updated to attempt 2 and markdown-free
        self.assertEqual(res["spl_query"], 'index=main (process="*cmd.exe*") | stats count')
        self.assertNotIn("```", res["spl_query"])

    def test_splunk_client_oneshot_search_sanitizes_tickmarks(self):
        """SplunkTestClient.execute_oneshot_search strips markdown fences even if passed directly."""
        dirty_input = "```spl\n```spl\nindex=main | stats count\n```\n```"
        client = SplunkTestClient()

        res = asyncio.run(client.execute_oneshot_search(dirty_input))
        self.assertEqual(res["query"], "search index=main | stats count")
        self.assertNotIn("```", res["query"])
        self.assertNotIn("```spl", res["query"])

    @patch("backend.app.validate_translation_bundle")
    @patch("backend.app.get_llm_client")
    @patch("backend.app.SplunkTestClient")
    def test_stream_translate_direct_handles_validate_translation_bundle_exception(
        self, mock_splunk_cls, mock_get_llm, mock_val
    ):
        """When validate_translation_bundle throws, SSE stream falls back gracefully and emits complete payload."""
        import json
        mock_val.side_effect = RuntimeError("Deterministic regex engine crash")

        mock_llm = MagicMock()
        mock_llm.complete = AsyncMock(return_value=VALID_LLM_OUTPUT)
        mock_get_llm.return_value = mock_llm

        mock_splunk = MagicMock()
        mock_splunk.execute_oneshot_search = AsyncMock(return_value={"success": True, "hit_count": 1})
        mock_splunk_cls.return_value = mock_splunk

        req = TranslateDirectRequest(
            raw_text=SAMPLE_ARCSIGHT_RULE,
            llm_config=LLMConfigPayload(provider="lm_studio"),
            deep_mode=True,
        )

        async def run_stream():
            events = []
            async for chunk in stream_translate_direct(req):
                for line in chunk.strip().split("\n"):
                    if line.startswith("data: "):
                        events.append(json.loads(line[6:]))
            return events

        events = asyncio.run(run_stream())
        self.assertTrue(len(events) >= 3)

        # No error events emitted
        error_events = [e for e in events if "error" in e and not e.get("type") == "result"]
        self.assertEqual(len(error_events), 0)

        # Final event must be complete result
        final_event = events[-1]
        self.assertEqual(final_event.get("type"), "result")
        self.assertEqual(final_event.get("status"), "complete")

        res = final_event["result"]
        self.assertTrue(res["success"])
        self.assertEqual(res["validation"]["overall_coverage_pct"], 0.0)
        self.assertFalse(res["validation"]["passed"])
        self.assertIn("Deterministic coverage audit failed", res["validation"]["kql"]["notes"][0])
        self.assertIn("Deterministic regex engine crash", res["validation"]["kql"]["notes"][0])

    def test_make_json_serializable_handles_complex_types(self):
        """Verify make_json_serializable recursively converts custom objects, sets, dates to JSON primitives."""
        import json
        from datetime import datetime, timezone

        class CustomClass:
            def __init__(self):
                self.name = "custom"
                self.val = 42

        complex_data = {
            "str": "hello",
            "int": 123,
            "set": {1, 2, 3},
            "custom": CustomClass(),
            "date": datetime(2026, 9, 9, tzinfo=timezone.utc),
            "nested": [CustomClass(), {"inner_set": {"a", "b"}}],
        }

        serialized = make_json_serializable(complex_data)
        # Must serialize cleanly with standard json.dumps
        json_str = json.dumps(serialized)
        self.assertIn('"name": "custom"', json_str)
        self.assertIn('"val": 42', json_str)
        self.assertIn("2026-09-09", json_str)

    @patch("backend.app.validate_translation_bundle")
    @patch("backend.app.get_llm_client")
    @patch("backend.app.SplunkTestClient")
    def test_execute_translate_direct_handles_validation_exception(
        self, mock_splunk_cls, mock_get_llm, mock_val
    ):
        """execute_translate_direct also falls back gracefully with 0% coverage on validation failure."""
        mock_val.side_effect = RuntimeError("Unexpected audit error")

        mock_llm = MagicMock()
        mock_llm.complete = AsyncMock(return_value=VALID_LLM_OUTPUT)
        mock_get_llm.return_value = mock_llm

        mock_splunk = MagicMock()
        mock_splunk.execute_oneshot_search = AsyncMock(return_value={"success": True, "hit_count": 1})
        mock_splunk_cls.return_value = mock_splunk

        req = TranslateDirectRequest(
            raw_text=SAMPLE_ARCSIGHT_RULE,
            llm_config=LLMConfigPayload(provider="lm_studio"),
            deep_mode=False,
        )

        res = asyncio.run(execute_translate_direct(req))
        self.assertTrue(res["success"])
        self.assertEqual(res["validation"]["overall_coverage_pct"], 0.0)
        self.assertFalse(res["validation"]["passed"])
        self.assertIn("Unexpected audit error", res["validation"]["kql"]["notes"][0])


if __name__ == "__main__":
    unittest.main()



