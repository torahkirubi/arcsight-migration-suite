"""
app.py - FastAPI Application for ArcSight Migration Suite

Provides endpoints for:
- /api/health: Background health check for FastAPI, LLM (LM Studio / Cloud), and Splunk
- /api/translate-direct: Deterministic ArcSight parsing + LLM direct translation to KQL/SPL + coverage validation
- /api/validate: Standalone query coverage verification
- /api/generate-runbook: LLM threat analysis & triage guide (STRICTLY NO MDE COVERAGE)
- /api/save-runbook: Merges human MDE verdict, writes git-ready .txt output
- /api/test-live-splunk: Read-only bounded oneshot search against Splunk REST API
- /api/audit-log: Query SQLite migration history & stats
"""

import asyncio
from datetime import datetime, timezone
import json
import os
import time
from typing import Any, Dict, List, Optional

try:
    from pydantic import BaseModel, Field
    HAS_PYDANTIC = True
except ImportError:
    HAS_PYDANTIC = False

    class BaseModel:  # type: ignore
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

    def Field(default=None, **kwargs):  # type: ignore
        return default

try:
    from fastapi import FastAPI, HTTPException, Query, Header, status
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse, StreamingResponse
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

    class HTTPException(Exception):  # type: ignore
        def __init__(self, status_code: int, detail: str = ""):
            self.status_code = status_code
            self.detail = detail
            super().__init__(f"HTTP {status_code}: {detail}")

    class StreamingResponse:  # type: ignore
        def __init__(self, content, media_type="text/event-stream", headers=None):
            self.content = content
            self.media_type = media_type
            self.headers = headers or {}

from backend.arcsight_parser import parse_arcsight_rule, ParsedArcSightRule
from backend.translation_validator import validate_query, validate_translation_bundle
from backend.llm_client import (
    get_llm_client,
    LLMError,
    LLMConnectionError,
    LLMTruncationError,
    LLMAuthError,
)
from backend.direct_translate_prompts import (
    DIRECT_TRANSLATE_SYSTEM_PROMPT,
    build_direct_translate_prompt,
    extract_queries_from_response,
    sanitize_query,
)
from backend.threat_analysis_prompts import (
    THREAT_ANALYSIS_SYSTEM_PROMPT,
    build_threat_analysis_prompt,
    parse_threat_analysis_response,
)
from backend.splunk_client import SplunkTestClient
from backend.audit_store import audit_store
from backend.git_exporter import generate_git_ready_text, save_git_ready_runbook

START_TIME = time.time()

if HAS_FASTAPI:
    app = FastAPI(
        title="ArcSight Migration Suite API",
        description="Migrate legacy ArcSight ESM correlation rules to Microsoft Defender XDR (KQL) and Splunk (SPL)",
        version="2.0.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
else:
    app = None


# --- Pydantic Request Models ---

class LLMConfigPayload(BaseModel):
    provider: Optional[str] = "lm_studio"
    model_name: Optional[str] = None
    custom_base_url: Optional[str] = None
    api_key: Optional[str] = None


class HealthCheckPayload(BaseModel):
    provider: Optional[str] = "lm_studio"
    custom_base_url: Optional[str] = None
    api_key: Optional[str] = None
    splunk_host: Optional[str] = None
    splunk_port: Optional[int] = None


class TranslateDirectRequest(BaseModel):
    raw_text: str = Field(..., description="Raw ArcSight ESM rule export text")
    llm_config: Optional[LLMConfigPayload] = Field(default_factory=LLMConfigPayload)
    deep_mode: Optional[bool] = Field(False, description="Enable autonomous Splunk testing and self-correction loop")


class ValidateQueryRequest(BaseModel):
    query_text: str
    target_language: str = "KQL"  # KQL or SPL
    required_terms: List[str] = Field(default_factory=list)
    exclusion_terms: List[str] = Field(default_factory=list)


class GenerateRunbookRequest(BaseModel):
    rule_name: str
    severity: str
    mitre_tactic: Optional[str] = None
    raw_condition: str
    kql_query: str
    spl_query: str
    llm_config: Optional[LLMConfigPayload] = Field(default_factory=LLMConfigPayload)


class MDECoverageInput(BaseModel):
    verdict: str = Field(..., description="Strictly human-entered MDE coverage verdict")
    notes: str = Field(..., description="Analyst justification and product review notes")
    reviewer_name: Optional[str] = "Detection Engineer"


class SaveRunbookRequest(BaseModel):
    rule_name: str
    severity: str
    priority: int
    mitre_tactic: Optional[str] = None
    mitre_source: str = "missing"
    mitre_uri: Optional[str] = None
    frequency_str: str = ""
    group_by: List[str] = Field(default_factory=list)
    kql_query: str
    kql_validation: Dict[str, Any]
    spl_query: str
    spl_validation: Dict[str, Any]
    threat_analysis: Dict[str, Any]
    mde_coverage: MDECoverageInput
    llm_model: Optional[str] = "qwen2.5-coder"


class LiveSplunkTestRequest(BaseModel):
    spl_query: str
    earliest_time: Optional[str] = "-24h"
    latest_time: Optional[str] = "now"
    max_events: Optional[int] = 25
    host: Optional[str] = None
    port: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None


async def _perform_health_check(
    provider: Optional[str],
    custom_base_url: Optional[str],
    api_key: Optional[str],
    splunk_host: Optional[str],
    splunk_port: Optional[int],
) -> Dict[str, Any]:
    uptime_seconds = round(time.time() - START_TIME, 1)

    # 1. FastAPI status
    api_status = {
        "status": "online",
        "uptime_seconds": uptime_seconds,
        "port": int(os.environ.get("PORT", 8001)),
        "database": "sqlite_ready",
    }

    # 2. LLM Client status (never logs api_key)
    llm = get_llm_client(
        provider=provider or "lm_studio",
        custom_base_url=custom_base_url,
        api_key=api_key,
    )
    llm_task = asyncio.create_task(llm.health_check())

    # 3. Splunk client status
    splunk = SplunkTestClient(host=splunk_host, port=splunk_port)
    splunk_task = asyncio.create_task(splunk.test_connection())

    llm_health, splunk_health = await asyncio.gather(llm_task, splunk_task, return_exceptions=True)

    if isinstance(llm_health, Exception):
        llm_res = {"status": "unreachable", "error": str(llm_health)}
    else:
        llm_res = llm_health

    if isinstance(splunk_health, Exception):
        splunk_res = {"status": "unreachable", "error": str(splunk_health)}
    else:
        splunk_res = splunk_health

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "services": {
            "fastapi": api_status,
            "llm": llm_res,
            "splunk": splunk_res,
        },
    }


def make_json_serializable(obj: Any) -> Any:
    """
    Recursively converts complex Python objects (custom classes, dataclasses,
    dates, sets) into standard JSON-serializable primitives (dict, list, str, int, float, bool, None).
    """
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, dict):
        return {str(k): make_json_serializable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [make_json_serializable(item) for item in obj]
    if hasattr(obj, "to_dict") and callable(obj.to_dict):
        try:
            return make_json_serializable(obj.to_dict())
        except Exception:
            pass
    if hasattr(obj, "__dict__"):
        try:
            return make_json_serializable(dict(obj.__dict__))
        except Exception:
            pass
    return str(obj)


async def _execute_translate_direct(payload: TranslateDirectRequest) -> Dict[str, Any]:
    """
    Direct translation pipeline:
    1. Deterministic regex extraction of ArcSight rule (zero LLM).
    2. LLM query translation to KQL & SPL (with Deep Mode autonomous self-correction loop if enabled).
    3. Deterministic coverage validation of generated queries.
    4. Audit logging to SQLite.
    """
    if not payload.raw_text.strip():
        raise HTTPException(status_code=400, detail="ArcSight raw rule text cannot be empty.")

    # Step 1: Deterministic Extraction
    parsed_rule = parse_arcsight_rule(payload.raw_text)

    # Step 2: LLM Translation
    llm_cfg = payload.llm_config or LLMConfigPayload()
    llm = get_llm_client(
        provider=llm_cfg.provider or "lm_studio",
        custom_base_url=llm_cfg.custom_base_url,
        api_key=llm_cfg.api_key,
        model_name=llm_cfg.model_name,
    )

    user_prompt = build_direct_translate_prompt(
        rule_name=parsed_rule.rule_name,
        severity=parsed_rule.severity,
        raw_condition=parsed_rule.raw_condition,
        frequency_str=parsed_rule.frequency.raw_frequency,
        group_by=parsed_rule.group_by_fields,
        mitre_tactic=parsed_rule.mitre_tactic,
        required_terms=parsed_rule.required_terms,
        exclusion_terms=parsed_rule.exclusion_terms,
    )

    deep_mode = bool(payload.deep_mode)
    max_retries = 3 if deep_mode else 1
    attempt = 0
    deep_mode_passed = False
    deep_mode_failed = False
    deep_mode_error: Optional[str] = None
    current_prompt = user_prompt

    kql_query = ""
    spl_query = ""
    llm_output = ""

    splunk_client = SplunkTestClient()

    while attempt < max_retries:
        if attempt > 0:
            await asyncio.sleep(3)
        attempt += 1
        temp = 0.1 if attempt == 1 else 0.2

        try:
            llm_output = await llm.complete(
                prompt=current_prompt,
                system_prompt=DIRECT_TRANSLATE_SYSTEM_PROMPT,
                temperature=temp,
            )
        except LLMConnectionError as exc:
            audit_store.log_event(
                rule_name=parsed_rule.rule_name,
                endpoint="/api/translate-direct",
                outcome="error",
                provider=llm_cfg.provider,
                details={"error": str(exc)},
            )
            raise HTTPException(
                status_code=503,
                detail=f"LLM Service Unreachable: {exc}. Please verify LM Studio or your cloud provider is running.",
            )
        except LLMTruncationError as exc:
            audit_store.log_event(
                rule_name=parsed_rule.rule_name,
                endpoint="/api/translate-direct",
                outcome="error",
                provider=llm_cfg.provider,
                details={"error": str(exc)},
            )
            raise HTTPException(
                status_code=422,
                detail=f"LLM Output Truncated: {exc}. The context length was exceeded.",
            )
        except Exception as exc:
            audit_store.log_event(
                rule_name=parsed_rule.rule_name,
                endpoint="/api/translate-direct",
                outcome="error",
                provider=llm_cfg.provider,
                details={"error": str(exc)},
            )
            raise HTTPException(status_code=500, detail=f"Translation Error: {str(exc)}")

        # Extract KQL & SPL blocks and aggressively sanitize markdown fences
        extracted_kql, extracted_spl = extract_queries_from_response(llm_output)
        if extracted_kql:
            kql_query = sanitize_query(extracted_kql)
        if extracted_spl:
            spl_query = sanitize_query(extracted_spl)

        # Ensure both kql_query and spl_query are completely raw strings before Splunk validation
        kql_query = sanitize_query(kql_query)
        spl_query = sanitize_query(spl_query)

        if not deep_mode:
            break

        # Deep Mode: Validate resulting SPL via local Splunk REST API
        try:
            splunk_val = await asyncio.wait_for(
                splunk_client.execute_oneshot_search(spl_query=spl_query, max_events=1),
                timeout=5.0,
            )
        except Exception as exc:
            splunk_val = {"success": False, "error": f"Splunk service unreachable: {exc}"}

        if splunk_val.get("success"):
            deep_mode_passed = True
            break
        else:
            err_msg = splunk_val.get("error") or "Unknown Splunk error"
            deep_mode_error = err_msg

            # If Splunk is unreachable (network/connection error), do not spin retries blaming query syntax
            if any(kw in err_msg.lower() for kw in ["unreachable", "connection", "connect", "timed out"]):
                break

            if attempt < max_retries:
                current_prompt = (
                    f"{user_prompt}\n\n"
                    f"Your previous attempt failed validation with this Splunk error: [{err_msg}]. "
                    f"Analyze the syntax failure and rewrite the SPL query. "
                    f"Reminder: When matching fields against patterns with wildcards (*) using the IN operator, always use | search Field IN (...) rather than | where. Splunk treats asterisks as literal characters inside where clauses. "
                    f"Do not append runtime relative time calculations like | where _time >= relative_time(...) unless explicitly requested."
                )
            else:
                deep_mode_failed = True

    if deep_mode and not deep_mode_passed and attempt >= max_retries:
        deep_mode_failed = True

    # Step 3: Deterministic Coverage Validation
    try:
        val_bundle = validate_translation_bundle(kql_query, spl_query, parsed_rule)
    except Exception as e:
        req_terms = list(getattr(parsed_rule, "required_terms", []) or [])
        excl_terms = list(getattr(parsed_rule, "exclusion_terms", []) or [])
        err_msg = f"Deterministic coverage audit failed: {e}"
        val_bundle = {
            "kql": {
                "target_language": "KQL",
                "passed": False,
                "coverage_pct": 0.0,
                "required_terms_checked": req_terms,
                "missing_required": req_terms,
                "exclusion_terms_checked": excl_terms,
                "missing_exclusions": excl_terms,
                "wrongly_included_as_match": [],
                "notes": [err_msg],
            },
            "spl": {
                "target_language": "SPL",
                "passed": False,
                "coverage_pct": 0.0,
                "required_terms_checked": req_terms,
                "missing_required": req_terms,
                "exclusion_terms_checked": excl_terms,
                "missing_exclusions": excl_terms,
                "wrongly_included_as_match": [],
                "notes": [err_msg],
            },
            "passed": False,
            "overall_coverage_pct": 0.0,
        }

    # Step 4: Splunk validation notes
    if deep_mode:
        if deep_mode_passed:
            val_bundle["spl"]["notes"].append(
                f"Deep Mode: SPL autonomously validated against Splunk in {attempt} attempt(s)."
            )
        elif deep_mode_failed:
            val_bundle["spl"]["notes"].append(
                f"Deep Mode Warning: Splunk validation failed after {attempt} attempt(s): {deep_mode_error}"
            )
        else:
            val_bundle["spl"]["notes"].append(
                f"Deep Mode Warning: Splunk service unreachable ({deep_mode_error}). Fallback to standard output."
            )
    else:
        # Optional live Splunk syntax validation if service is available
        try:
            splunk_conn = await asyncio.wait_for(splunk_client.test_connection(), timeout=1.0)
            if splunk_conn.get("status") == "connected":
                splunk_val = await asyncio.wait_for(
                    splunk_client.execute_oneshot_search(spl_query=spl_query, max_events=1),
                    timeout=3.0,
                )
                if splunk_val.get("success"):
                    val_bundle["spl"]["notes"].append(
                        f"Splunk REST Validation: Syntax verified on Splunk {splunk_conn.get('version', '')} ({splunk_val.get('hit_count', 0)} matching events)."
                    )
                elif splunk_val.get("error"):
                    val_bundle["spl"]["notes"].append(
                        f"Splunk REST Validation Error: {splunk_val.get('error')}"
                    )
        except Exception:
            pass

    outcome = "passed" if val_bundle["passed"] else "warning"
    try:
        audit_store.log_event(
            rule_name=parsed_rule.rule_name,
            endpoint="/api/translate-direct",
            outcome=outcome,
            provider=llm_cfg.provider,
            model=llm_cfg.model_name or "default",
            coverage_pct=val_bundle["overall_coverage_pct"],
            details={
                "kql_passed": val_bundle["kql"]["passed"],
                "spl_passed": val_bundle["spl"]["passed"],
                "mitre_source": parsed_rule.mitre_source,
                "deep_mode": deep_mode,
                "deep_mode_passed": deep_mode_passed,
                "deep_mode_attempts": attempt,
            },
        )
    except Exception:
        pass

    parsed_rule_dict = (
        parsed_rule.to_dict()
        if hasattr(parsed_rule, "to_dict") and callable(parsed_rule.to_dict)
        else {"rule_name": getattr(parsed_rule, "rule_name", "Unknown Rule")}
    )

    final_payload = {
        "success": True,
        "parsed_rule": parsed_rule_dict,
        "kql_query": kql_query,
        "spl_query": spl_query,
        "validation": val_bundle,
        "raw_llm_output": llm_output,
        "deep_mode": deep_mode,
        "deep_mode_passed": deep_mode_passed,
        "deep_mode_attempts": attempt,
        "deep_mode_failed": deep_mode_failed,
        "deep_mode_error": deep_mode_error,
    }

    return make_json_serializable(final_payload)


async def _stream_translate_direct(payload: TranslateDirectRequest):
    """
    Yields Server-Sent Events (SSE) status updates and final translated payload:
    1. Status: Deterministic extraction
    2. Status: LLM translation attempt
    3. Status: Splunk REST search test
    4. Status: Self-correction (if Splunk error)
    5. Final: Full KQL/SPL payload with validation
    """
    try:
        if not payload.raw_text.strip():
            yield f"data: {json.dumps({'error': 'ArcSight raw rule text cannot be empty.', 'status': 'Error: empty input'})}\n\n"
            return

        yield f"data: {json.dumps({'status': 'Deterministic extraction completed (ArcSight regex parser)'})}\n\n"
        parsed_rule = parse_arcsight_rule(payload.raw_text)

        llm_cfg = payload.llm_config or LLMConfigPayload()
        llm = get_llm_client(
            provider=llm_cfg.provider or "lm_studio",
            custom_base_url=llm_cfg.custom_base_url,
            api_key=llm_cfg.api_key,
            model_name=llm_cfg.model_name,
        )

        user_prompt = build_direct_translate_prompt(
            rule_name=parsed_rule.rule_name,
            severity=parsed_rule.severity,
            raw_condition=parsed_rule.raw_condition,
            frequency_str=parsed_rule.frequency.raw_frequency,
            group_by=parsed_rule.group_by_fields,
            mitre_tactic=parsed_rule.mitre_tactic,
            required_terms=parsed_rule.required_terms,
            exclusion_terms=parsed_rule.exclusion_terms,
        )

        max_retries = 3
        attempt = 0
        deep_mode_passed = False
        deep_mode_failed = False
        deep_mode_error: Optional[str] = None
        current_prompt = user_prompt

        kql_query = ""
        spl_query = ""
        llm_output = ""

        splunk_client = SplunkTestClient()

        while attempt < max_retries:
            if attempt > 0:
                yield f"data: {json.dumps({'status': 'Rate limit cooldown (3s) before next LLM attempt...'})}\n\n"
                await asyncio.sleep(3)
            attempt += 1
            temp = 0.1 if attempt == 1 else 0.2

            if attempt == 1:
                yield f"data: {json.dumps({'status': 'Drafting initial SPL...'})}\n\n"
            else:
                yield f"data: {json.dumps({'status': f'Parser failed, rewriting... (Attempt {attempt}/{max_retries})'})}\n\n"

            try:
                llm_output = await llm.complete(
                    prompt=current_prompt,
                    system_prompt=DIRECT_TRANSLATE_SYSTEM_PROMPT,
                    temperature=temp,
                )
            except LLMConnectionError as exc:
                audit_store.log_event(
                    rule_name=parsed_rule.rule_name,
                    endpoint="/api/translate-direct",
                    outcome="error",
                    provider=llm_cfg.provider,
                    details={"error": str(exc)},
                )
                yield f"data: {json.dumps({'error': f'LLM Service Unreachable: {exc}', 'status': 'Error: LLM unreachable'})}\n\n"
                return
            except LLMTruncationError as exc:
                audit_store.log_event(
                    rule_name=parsed_rule.rule_name,
                    endpoint="/api/translate-direct",
                    outcome="error",
                    provider=llm_cfg.provider,
                    details={"error": str(exc)},
                )
                yield f"data: {json.dumps({'error': f'LLM Output Truncated: {exc}', 'status': 'Error: context length exceeded'})}\n\n"
                return
            except Exception as exc:
                audit_store.log_event(
                    rule_name=parsed_rule.rule_name,
                    endpoint="/api/translate-direct",
                    outcome="error",
                    provider=llm_cfg.provider,
                    details={"error": str(exc)},
                )
                yield f"data: {json.dumps({'error': f'Translation Error: {exc}', 'status': f'Error: {exc}'})}\n\n"
                return

            # Extract KQL & SPL blocks and aggressively sanitize markdown fences
            extracted_kql, extracted_spl = extract_queries_from_response(llm_output)
            if extracted_kql:
                kql_query = sanitize_query(extracted_kql)
            if extracted_spl:
                spl_query = sanitize_query(extracted_spl)

            # Ensure both kql_query and spl_query are completely raw strings before Splunk validation
            kql_query = sanitize_query(kql_query)
            spl_query = sanitize_query(spl_query)

            yield f"data: {json.dumps({'status': f'Testing against Splunk (Attempt {attempt})...'})}\n\n"

            try:
                splunk_val = await asyncio.wait_for(
                    splunk_client.execute_oneshot_search(spl_query=spl_query, max_events=1),
                    timeout=5.0,
                )
            except Exception as exc:
                splunk_val = {"success": False, "error": f"Splunk service unreachable: {exc}"}

            if splunk_val.get("success"):
                deep_mode_passed = True
                yield f"data: {json.dumps({'status': f'Splunk validation PASSED on attempt {attempt} (200 OK)'})}\n\n"
                break
            else:
                err_msg = splunk_val.get("error") or "Unknown Splunk error"
                deep_mode_error = err_msg

                if any(kw in err_msg.lower() for kw in ["unreachable", "connection", "connect", "timed out"]):
                    yield f"data: {json.dumps({'status': f'Splunk container unreachable ({err_msg}). Falling back gracefully...'})}\n\n"
                    break

                if attempt < max_retries:
                    yield f"data: {json.dumps({'status': f'Splunk validation failed ({err_msg}). Preparing self-correction prompt...'})}\n\n"
                    current_prompt = (
                        f"{user_prompt}\n\n"
                        f"Your previous attempt failed validation with this Splunk error: [{err_msg}]. "
                        f"Analyze the syntax failure and rewrite the SPL query. "
                        f"Reminder: When matching fields against patterns with wildcards (*) using the IN operator, always use | search Field IN (...) rather than | where. Splunk treats asterisks as literal characters inside where clauses. "
                        f"Do not append runtime relative time calculations like | where _time >= relative_time(...) unless explicitly requested."
                    )
                else:
                    deep_mode_failed = True
                    yield f"data: {json.dumps({'status': f'Max retries exhausted ({attempt}/{max_retries}). Retaining best candidate query.'})}\n\n"

        if not deep_mode_passed and attempt >= max_retries:
            deep_mode_failed = True

        yield f"data: {json.dumps({'status': 'Running deterministic coverage validation (KQL & SPL)...'})}\n\n"

        # Dedicated try...except block around validate_translation_bundle
        try:
            val_bundle = validate_translation_bundle(kql_query, spl_query, parsed_rule)
        except Exception as e:
            req_terms = list(getattr(parsed_rule, "required_terms", []) or [])
            excl_terms = list(getattr(parsed_rule, "exclusion_terms", []) or [])
            err_msg = f"Deterministic coverage audit failed: {e}"
            val_bundle = {
                "kql": {
                    "target_language": "KQL",
                    "passed": False,
                    "coverage_pct": 0.0,
                    "required_terms_checked": req_terms,
                    "missing_required": req_terms,
                    "exclusion_terms_checked": excl_terms,
                    "missing_exclusions": excl_terms,
                    "wrongly_included_as_match": [],
                    "notes": [err_msg],
                },
                "spl": {
                    "target_language": "SPL",
                    "passed": False,
                    "coverage_pct": 0.0,
                    "required_terms_checked": req_terms,
                    "missing_required": req_terms,
                    "exclusion_terms_checked": excl_terms,
                    "missing_exclusions": excl_terms,
                    "wrongly_included_as_match": [],
                    "notes": [err_msg],
                },
                "passed": False,
                "overall_coverage_pct": 0.0,
            }

        if deep_mode_passed:
            val_bundle["spl"]["notes"].append(
                f"Deep Mode: SPL autonomously validated against Splunk in {attempt} attempt(s)."
            )
        elif deep_mode_failed:
            val_bundle["spl"]["notes"].append(
                f"Deep Mode Warning: Splunk validation failed after {attempt} attempt(s): {deep_mode_error}"
            )
        else:
            val_bundle["spl"]["notes"].append(
                f"Deep Mode Warning: Splunk service unreachable ({deep_mode_error}). Fallback to standard output."
            )

        outcome = "passed" if val_bundle["passed"] else "warning"
        try:
            audit_store.log_event(
                rule_name=parsed_rule.rule_name,
                endpoint="/api/translate-direct",
                outcome=outcome,
                provider=llm_cfg.provider,
                model=llm_cfg.model_name or "default",
                coverage_pct=val_bundle["overall_coverage_pct"],
                details={
                    "kql_passed": val_bundle["kql"]["passed"],
                    "spl_passed": val_bundle["spl"]["passed"],
                    "mitre_source": parsed_rule.mitre_source,
                    "deep_mode": True,
                    "deep_mode_passed": deep_mode_passed,
                    "deep_mode_attempts": attempt,
                },
            )
        except Exception:
            pass

        parsed_rule_dict = (
            parsed_rule.to_dict()
            if hasattr(parsed_rule, "to_dict") and callable(parsed_rule.to_dict)
            else {"rule_name": getattr(parsed_rule, "rule_name", "Unknown Rule")}
        )

        final_payload = {
            "success": True,
            "parsed_rule": parsed_rule_dict,
            "kql_query": kql_query,
            "spl_query": spl_query,
            "validation": val_bundle,
            "raw_llm_output": llm_output,
            "deep_mode": True,
            "deep_mode_passed": deep_mode_passed,
            "deep_mode_attempts": attempt,
            "deep_mode_failed": deep_mode_failed,
            "deep_mode_error": deep_mode_error,
        }

        sanitized_final_payload = make_json_serializable(final_payload)
        yield f"data: {json.dumps({'type': 'result', 'status': 'complete', 'result': sanitized_final_payload}, default=str)}\n\n"
    except Exception as e:
        yield f"data: {json.dumps({'error': str(e), 'status': f'Error: {e}'}, default=str)}\n\n"


execute_translate_direct = _execute_translate_direct
stream_translate_direct = _stream_translate_direct
translate_direct = _execute_translate_direct


# --- Route Handlers ---

if HAS_FASTAPI:

    @app.post("/api/health")
    async def post_system_health(
        payload: HealthCheckPayload,
        authorization: Optional[str] = Header(None),
    ):
        """
        Secure health check endpoint: accepts credentials via JSON payload or Authorization header.
        Prevents API keys from leaking into HTTP query parameters and web server access logs.
        """
        resolved_key = payload.api_key
        if authorization and authorization.lower().startswith("bearer "):
            header_token = authorization[7:].strip()
            if header_token:
                resolved_key = header_token

        return await _perform_health_check(
            provider=payload.provider,
            custom_base_url=payload.custom_base_url,
            api_key=resolved_key,
            splunk_host=payload.splunk_host,
            splunk_port=payload.splunk_port,
        )

    @app.get("/api/health")
    async def get_system_health(
        provider: Optional[str] = Query("lm_studio"),
        custom_base_url: Optional[str] = Query(None),
        splunk_host: Optional[str] = Query(None),
        splunk_port: Optional[int] = Query(None),
        authorization: Optional[str] = Header(None),
    ):
        """
        Lightweight GET health check.
        SECURITY NOTICE: api_key is intentionally NOT accepted as a URL query parameter
        to prevent credential leakage into Docker access logs. Pass via 'Authorization: Bearer'
        or use POST /api/health with a JSON body.
        """
        api_key = None
        if authorization and authorization.lower().startswith("bearer "):
            api_key = authorization[7:].strip()

        return await _perform_health_check(
            provider=provider,
            custom_base_url=custom_base_url,
            api_key=api_key,
            splunk_host=splunk_host,
            splunk_port=splunk_port,
        )

    @app.post("/api/translate-direct")
    async def translate_direct(payload: TranslateDirectRequest):
        if payload.deep_mode:
            return StreamingResponse(
                _stream_translate_direct(payload),
                media_type="text/event-stream",
                headers={
                    "Cache-Control": "no-cache",
                    "Connection": "keep-alive",
                    "X-Accel-Buffering": "no",
                },
            )
        return await _execute_translate_direct(payload)

    @app.post("/api/validate")
    async def validate_standalone(payload: ValidateQueryRequest):
        """
        Standalone coverage validation against user-modified queries.
        """
        res = validate_query(
            query_text=payload.query_text,
            required_terms=payload.required_terms,
            exclusion_terms=payload.exclusion_terms,
            target_language=payload.target_language,
        )
        return res.to_dict()

    @app.post("/api/generate-runbook")
    async def generate_runbook(payload: GenerateRunbookRequest):
        """
        Generates threat analysis and Tier-1 triage guide.
        STRICT SAFETY BOUNDARY: MDE Coverage is explicitly excluded from LLM generation.
        """
        llm_cfg = payload.llm_config or LLMConfigPayload()
        llm = get_llm_client(
            provider=llm_cfg.provider or "lm_studio",
            custom_base_url=llm_cfg.custom_base_url,
            api_key=llm_cfg.api_key,
            model_name=llm_cfg.model_name,
        )

        prompt = build_threat_analysis_prompt(
            rule_name=payload.rule_name,
            severity=payload.severity,
            mitre_tactic=payload.mitre_tactic or "Unknown",
            raw_condition=payload.raw_condition,
            kql_query=payload.kql_query,
            spl_query=payload.spl_query,
        )

        try:
            output = await llm.complete(
                prompt=prompt,
                system_prompt=THREAT_ANALYSIS_SYSTEM_PROMPT,
                temperature=0.2,
            )
            analysis = parse_threat_analysis_response(output)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Threat Analysis generation failed: {exc}")

        audit_store.log_event(
            rule_name=payload.rule_name,
            endpoint="/api/generate-runbook",
            outcome="success",
            provider=llm_cfg.provider,
            model=llm_cfg.model_name,
        )

        return {
            "success": True,
            "threat_analysis": analysis,
        }

    @app.post("/api/save-runbook")
    async def save_runbook(payload: SaveRunbookRequest):
        """
        Merges LLM threat analysis, translated queries, and STRICTLY HUMAN MDE verdict,
        then writes a Git-ready .txt runbook to disk.
        """
        # Strict validation: MDE coverage must not be empty!
        if not payload.mde_coverage.verdict or not payload.mde_coverage.verdict.strip():
            raise HTTPException(
                status_code=400,
                detail="Safety Error: Microsoft Defender (MDE) coverage verdict must be provided by human analyst.",
            )

        runbook_text = generate_git_ready_text(
            rule_name=payload.rule_name,
            severity=payload.severity,
            priority=payload.priority,
            mitre_tactic=payload.mitre_tactic,
            mitre_source=payload.mitre_source,
            mitre_uri=payload.mitre_uri,
            frequency_str=payload.frequency_str,
            group_by=payload.group_by,
            kql_query=payload.kql_query,
            kql_validation=payload.kql_validation,
            spl_query=payload.spl_query,
            spl_validation=payload.spl_validation,
            threat_analysis=payload.threat_analysis,
            mde_verdict=payload.mde_coverage.verdict,
            mde_notes=payload.mde_coverage.notes,
            reviewer_name=payload.mde_coverage.reviewer_name or "Detection Engineer",
            llm_model=payload.llm_model or "qwen2.5-coder",
        )

        res = save_git_ready_runbook(payload.rule_name, runbook_text)

        audit_store.log_event(
            rule_name=payload.rule_name,
            endpoint="/api/save-runbook",
            outcome="success",
            details={
                "filename": res["filename"],
                "mde_verdict": payload.mde_coverage.verdict,
            },
        )

        return {
            "success": True,
            "filename": res["filename"],
            "file_path": res["file_path"],
            "content": runbook_text,
            "message": f"Runbook successfully generated and saved to {res['filename']}",
        }

    @app.post("/api/test-live-splunk")
    @app.post("/api/test-splunk")
    async def test_live_splunk(payload: LiveSplunkTestRequest):
        """
        Executes a bounded, read-only oneshot search against real Splunk REST API.
        """
        client = SplunkTestClient(
            host=payload.host,
            port=payload.port,
            username=payload.username,
            password=payload.password,
            token=payload.token,
        )

        res = await client.execute_oneshot_search(
            spl_query=payload.spl_query,
            earliest_time=payload.earliest_time or "-24h",
            latest_time=payload.latest_time or "now",
            max_events=payload.max_events or 25,
        )

        audit_store.log_event(
            rule_name="Live Splunk Test",
            endpoint="/api/test-live-splunk",
            outcome="success" if res.get("success") else "failed",
            details=res,
        )

        return res

    @app.get("/api/audit-log")
    async def get_audit_log(
        limit: int = Query(50, ge=1, le=200),
        offset: int = Query(0, ge=0),
        rule_name: Optional[str] = Query(None),
    ):
        """
        Returns migration audit history from persistent SQLite store.
        """
        history = audit_store.get_history(limit=limit, offset=offset, rule_name_filter=rule_name)
        stats = audit_store.get_stats()
        return {
            "history": history,
            "stats": stats,
        }

