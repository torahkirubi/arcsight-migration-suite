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
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

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
    from fastapi import FastAPI, HTTPException, Query, Header, status, Depends, APIRouter
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

    class JSONResponse:  # type: ignore
        def __init__(self, content, status_code=200, headers=None):
            self.content = content
            self.status_code = status_code
            self.headers = headers or {}

    def Header(default=None, **kwargs):  # type: ignore
        return default

    def Query(default=None, **kwargs):  # type: ignore
        return default

    def Depends(dependency=None):  # type: ignore
        return dependency

    class status:  # type: ignore
        HTTP_200_OK = 200
        HTTP_201_CREATED = 201
        HTTP_400_BAD_REQUEST = 400
        HTTP_401_UNAUTHORIZED = 401
        HTTP_404_NOT_FOUND = 404
        HTTP_500_INTERNAL_SERVER_ERROR = 500

    class CORSMiddleware:  # type: ignore
        pass

    class Route:  # type: ignore
        def __init__(self, path: str, endpoint: Any, methods: List[str], status_code: int = 200):
            self.path = path
            self.endpoint = endpoint
            self.methods = set(methods)
            self.status_code = status_code

    class APIRouter:  # type: ignore
        def __init__(self, prefix="", *args, **kwargs):
            self.prefix = prefix
            self.routes = []

        def post(self, path: str, *args, **kwargs):
            full_path = self.prefix + path
            status_code = kwargs.get("status_code", 200)
            def decorator(func):
                self.routes.append(Route(full_path, func, ["POST"], status_code=status_code))
                return func
            return decorator

        def get(self, path: str, *args, **kwargs):
            full_path = self.prefix + path
            status_code = kwargs.get("status_code", 200)
            def decorator(func):
                self.routes.append(Route(full_path, func, ["GET"], status_code=status_code))
                return func
            return decorator

    class FastAPI:  # type: ignore
        def __init__(self, *args, **kwargs):
            self.routes = []

        def post(self, path: str, *args, **kwargs):
            status_code = kwargs.get("status_code", 200)
            def decorator(func):
                self.routes.append(Route(path, func, ["POST"], status_code=status_code))
                return func
            return decorator

        def get(self, path: str, *args, **kwargs):
            status_code = kwargs.get("status_code", 200)
            def decorator(func):
                self.routes.append(Route(path, func, ["GET"], status_code=status_code))
                return func
            return decorator

        def include_router(self, router, *args, **kwargs):
            prefix = getattr(router, "prefix", "")
            for r in getattr(router, "routes", []):
                path = r.path
                if prefix and not path.startswith(prefix):
                    path = prefix + path
                self.routes.append(Route(path, r.endpoint, list(r.methods), status_code=getattr(r, "status_code", 200)))

        def add_middleware(self, *args, **kwargs):
            pass

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
from backend.sentinel_client import SentinelClient
from backend.telemetry_tuner import apply_exclusions, calculate_dynamic_threshold
from backend.audit_store import audit_store
from backend.git_exporter import generate_git_ready_text, save_git_ready_runbook
from backend.auth_vault import (
    auth_router,
    init_auth_vault_db,
    VaultService,
    get_current_user,
    create_jwt_token,
    verify_jwt_token,
)

START_TIME = time.time()

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

# Mount Authentication & Vault router
app.include_router(auth_router)

# Initialize Auth & Vault SQLite database
init_auth_vault_db()

if hasattr(app, "on_event"):
    @app.on_event("startup")
    def startup_auth_vault():
        init_auth_vault_db()

ACTIVE_INTEGRATIONS: Dict[str, Any] = {
    "sentinel": {},
}


# --- Pydantic Request Models ---

class SentinelSettings(BaseModel):
    tenant_id: str = ""
    client_id: str = ""
    client_secret: str = ""
    workspace_id: str = ""


class LLMSettingsPayload(BaseModel):
    provider: str
    api_key: str
    model_name: Optional[str] = None


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

    # Dynamic Sentinel ASIM schema resolution
    sentinel_client = SentinelClient()
    asim_mappings: Dict[str, str] = {}
    candidate_fields = list(parsed_rule.referenced_fields)
    for c in parsed_rule.clauses:
        if c.field_name and c.field_name not in candidate_fields:
            candidate_fields.append(c.field_name)

    for field in candidate_fields:
        resolved = sentinel_client.resolve_field_mapping(field)
        if resolved and resolved != field:
            asim_mappings[field] = resolved

    user_prompt = build_direct_translate_prompt(
        rule_name=parsed_rule.rule_name,
        severity=parsed_rule.severity,
        raw_condition=parsed_rule.raw_condition,
        frequency_str=parsed_rule.frequency.raw_frequency,
        group_by=parsed_rule.group_by_fields,
        mitre_tactic=parsed_rule.mitre_tactic,
        required_terms=parsed_rule.required_terms,
        exclusion_terms=parsed_rule.exclusion_terms,
        asim_mappings=asim_mappings,
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

    # Step 5: Sentinel Telemetry Baseline & Dynamic Threshold
    try:
        kql_telemetry = sentinel_client.execute_kql_query(query_text=kql_query, timespan_days=7)
        baseline_count = kql_telemetry.get("row_count", 0) if isinstance(kql_telemetry, dict) else 0
    except Exception:
        baseline_count = 0

    static_threshold = 0
    if hasattr(parsed_rule, "frequency") and parsed_rule.frequency:
        static_threshold = getattr(parsed_rule.frequency, "event_count", 0) or 0

    tuning_rec = calculate_dynamic_threshold(
        baseline_event_count=baseline_count,
        static_rule_threshold=static_threshold,
    )

    final_payload = {
        "success": True,
        "parsed_rule": parsed_rule_dict,
        "kql_query": kql_query,
        "spl_query": spl_query,
        "validation": val_bundle,
        "raw_llm_output": llm_output,
        "tuning_recommendation": tuning_rec,
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

        # Dynamic Sentinel ASIM schema resolution
        sentinel_client = SentinelClient()
        asim_mappings: Dict[str, str] = {}
        candidate_fields = list(parsed_rule.referenced_fields)
        for c in parsed_rule.clauses:
            if c.field_name and c.field_name not in candidate_fields:
                candidate_fields.append(c.field_name)

        for field in candidate_fields:
            resolved = sentinel_client.resolve_field_mapping(field)
            if resolved and resolved != field:
                asim_mappings[field] = resolved

        user_prompt = build_direct_translate_prompt(
            rule_name=parsed_rule.rule_name,
            severity=parsed_rule.severity,
            raw_condition=parsed_rule.raw_condition,
            frequency_str=parsed_rule.frequency.raw_frequency,
            group_by=parsed_rule.group_by_fields,
            mitre_tactic=parsed_rule.mitre_tactic,
            required_terms=parsed_rule.required_terms,
            exclusion_terms=parsed_rule.exclusion_terms,
            asim_mappings=asim_mappings,
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

        yield f"data: {json.dumps({'status': 'Querying Sentinel historical baseline & calculating dynamic threshold...'})}\n\n"

        # Step 5: Sentinel Telemetry Baseline & Dynamic Threshold
        try:
            kql_telemetry = sentinel_client.execute_kql_query(query_text=kql_query, timespan_days=7)
            baseline_count = kql_telemetry.get("row_count", 0) if isinstance(kql_telemetry, dict) else 0
        except Exception:
            baseline_count = 0

        static_threshold = 0
        if hasattr(parsed_rule, "frequency") and parsed_rule.frequency:
            static_threshold = getattr(parsed_rule.frequency, "event_count", 0) or 0

        tuning_rec = calculate_dynamic_threshold(
            baseline_event_count=baseline_count,
            static_rule_threshold=static_threshold,
        )

        final_payload = {
            "success": True,
            "parsed_rule": parsed_rule_dict,
            "kql_query": kql_query,
            "spl_query": spl_query,
            "validation": val_bundle,
            "raw_llm_output": llm_output,
            "tuning_recommendation": tuning_rec,
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

if app is not None:

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

    @app.post("/api/settings/sentinel")
    async def save_sentinel_settings(payload: SentinelSettings):
        """
        Stores Sentinel credentials in the active integration registry.
        """
        ACTIVE_INTEGRATIONS["sentinel"] = {
            "tenant_id": payload.tenant_id,
            "client_id": payload.client_id,
            "client_secret": payload.client_secret,
            "workspace_id": payload.workspace_id,
        }
        return {
            "status": "success",
            "success": True,
            "message": "Credentials saved",
        }

    @app.post("/api/settings/llm")
    async def save_llm_settings(payload: LLMSettingsPayload):
        """
        Persists LLM API keys to SQLite vault and immediately updates environment variables.
        """
        if not payload.api_key or not payload.api_key.strip():
            raise HTTPException(status_code=400, detail="API key cannot be empty")

        provider_norm = payload.provider.strip().lower()
        api_key_clean = payload.api_key.strip()

        vault_service = VaultService()
        # Save secret under the exact provider passed
        vault_service.save_secret(service_name=payload.provider, plaintext=api_key_clean)

        # Synchronize Gemini keys and environment
        if provider_norm in ("gemini", "cloud_gemini", "google"):
            vault_service.save_secret(service_name="GEMINI_API_KEY", plaintext=api_key_clean)
            vault_service.save_secret(service_name="gemini_api_key", plaintext=api_key_clean)
            os.environ["GEMINI_API_KEY"] = api_key_clean

        # Synchronize OpenAI keys and environment
        if provider_norm in ("openai", "cloud_openai"):
            vault_service.save_secret(service_name="OPENAI_API_KEY", plaintext=api_key_clean)
            vault_service.save_secret(service_name="openai_api_key", plaintext=api_key_clean)
            os.environ["OPENAI_API_KEY"] = api_key_clean

        return {
            "success": True,
            "message": f"{payload.provider} key secured in vault",
        }

    @app.get("/api/settings/llm")
    async def get_llm_settings():
        """
        Returns masked status of configured LLM API keys in vault and environment.
        """
        vault_service = VaultService()
        gemini_key = vault_service.get_secret("GEMINI_API_KEY") or os.environ.get("GEMINI_API_KEY")
        openai_key = vault_service.get_secret("OPENAI_API_KEY") or os.environ.get("OPENAI_API_KEY")
        return {
            "gemini_configured": bool(gemini_key),
            "openai_configured": bool(openai_key),
        }

    @app.post("/api/settings/sentinel/test")
    async def test_sentinel_connection(payload: SentinelSettings):
        """
        Temporarily instantiates SentinelClient with submitted credentials and tests authentication.
        """
        try:
            client = SentinelClient(
                tenant_id=payload.tenant_id,
                client_id=payload.client_id,
                client_secret=payload.client_secret,
                workspace_id=payload.workspace_id,
            )
            auth_token = client.authenticate()
            if not auth_token and not client.is_authenticated:
                return {
                    "success": False,
                    "error": "Authentication failed: invalid credentials or token",
                }
            return {
                "success": True,
                "message": "Successfully authenticated with Sentinel",
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
            }


class NoiseDiagnostics(BaseModel):
    noise_source: str
    affected_entities: List[Any] = Field(default_factory=list)
    mitigation_steps: List[str] = Field(default_factory=list)


class TuneRequest(BaseModel):
    raw_kql: str
    current_threshold: Optional[int] = 1


class TuneResponse(BaseModel):
    original_threshold: int
    suggested_threshold: int
    tuning_rationale: str
    noise_diagnostics: Optional[NoiseDiagnostics] = None
    tuned_kql: Optional[str] = None


NOISE_DIAGNOSTICS_SYSTEM_PROMPT = """You are a Microsoft Sentinel and KQL detection engineering expert.
Analyze the provided noisy telemetry clusters and provide root-cause diagnostics and an auto-mitigated KQL query.

CRITICAL FIELD RULES:
1. NEVER use generic placeholder field names such as "Object", "Entity", or "Target".
2. You must ONLY use real column names present in the input query and sample records:
   - For hostnames or machines, ALWAYS use: Computer
   - For usernames, ALWAYS use: AccountName
   - For processes, ALWAYS use: ProcessName
   - For commands, ALWAYS use: CommandLine
   - For event IDs, ALWAYS use: EventID
3. When constructing the auto-mitigated query, inject exclusions that specifically target noisy entities (such as AccountName !in ('svc-scanner', 'svc-backup') or specific CommandLine patterns) rather than filtering out all hostnames.
4. Return valid JSON matching the schema: {"noise_source": "...", "affected_entities": [...], "mitigation_steps": "...", "mitigated_kql": "..."}
"""


async def diagnose_telemetry_noise(
    raw_kql: str,
    sample_records: List[Dict[str, Any]],
    llm_client: Any,
) -> Optional[Dict[str, Any]]:
    """Analyzes sample telemetry events via LLM to extract noise diagnostics."""
    if not sample_records or len(sample_records) == 0:
        logger.warning("Diagnostics pipeline skipped: sample_records is empty")
        return None
    if not llm_client:
        logger.warning("Diagnostics pipeline skipped: llm_client is None")
        return None

    prompt = (
        f"KQL Detection Query:\n```kql\n{raw_kql}\n```\n\n"
        f"Sample Telemetry Records (take 10):\n"
        f"```json\n{json.dumps(sample_records, indent=2)}\n```\n\n"
        "Identify the noise source, affected entities, and recommended KQL mitigation exclusions."
    )

    try:
        import inspect
        if inspect.iscoroutinefunction(llm_client.complete):
            raw_response = await llm_client.complete(
                prompt=prompt,
                system_prompt=NOISE_DIAGNOSTICS_SYSTEM_PROMPT,
                temperature=0.1,
                max_tokens=8192,
            )
        else:
            raw_response = llm_client.complete(
                prompt=prompt,
                system_prompt=NOISE_DIAGNOSTICS_SYSTEM_PROMPT,
                temperature=0.1,
                max_tokens=8192,
            )

        if not raw_response or not isinstance(raw_response, str):
            logger.error(f"Diagnostics pipeline failed: LLM response empty or non-string: {raw_response!r}")
            return None

        cleaned = raw_response.strip()

        # Defensively strip markdown code fences (e.g. ```json ... ``` or ``` ...)
        if "```" in cleaned:
            fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", cleaned, re.IGNORECASE)
            if fence_match:
                cleaned = fence_match.group(1).strip()
            else:
                cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE).strip()
                cleaned = re.sub(r"\s*```$", "", cleaned).strip()

        parsed = None
        # Attempt standard JSON parse
        try:
            parsed = json.loads(cleaned)
        except Exception as json_err:
            # Fallback 1: Extract first JSON object delimited by { ... }
            brace_match = re.search(r"(\{[\s\S]*\})", cleaned)
            if brace_match:
                try:
                    parsed = json.loads(brace_match.group(1))
                except Exception:
                    pass

        # Fallback 2: Regex key-value extraction for partial/truncated JSON or alternate formatting
        if not isinstance(parsed, dict):
            parsed = {}
            ns_match = re.search(r'"(?:noise_source|root_cause)"\s*:\s*"([^"]+)"', cleaned)
            if ns_match:
                parsed["noise_source"] = ns_match.group(1)

            ent_match = re.search(r'"(?:affected_entities|noise_entities)"\s*:\s*\[([^\]]*)\]', cleaned)
            if ent_match:
                parsed["affected_entities"] = re.findall(r'"([^"]+)"', ent_match.group(1))

            mit_match = re.search(r'"(?:mitigation_steps|mitigated_kql)"\s*:\s*(\[[^\]]*\]|"[^"]+")', cleaned)
            if mit_match:
                val = mit_match.group(1)
                if val.startswith("["):
                    parsed["mitigation_steps"] = re.findall(r'"([^"]+)"', val)
                else:
                    parsed["mitigation_steps"] = [val.strip('"')]

        # Extract values with support for alternate aliases
        noise_source = str(parsed.get("noise_source") or parsed.get("root_cause") or "").strip()
        if not noise_source:
            noise_source = "Unknown Noise Source"

        raw_entities = parsed.get("affected_entities") or parsed.get("noise_entities") or []
        if not isinstance(raw_entities, list):
            raw_entities = [raw_entities]
        affected_entities = []
        for e in raw_entities:
            if isinstance(e, dict):
                affected_entities.append(e)
            elif e is not None and str(e).strip():
                affected_entities.append(str(e).strip())

        mitigation_steps = parsed.get("mitigation_steps") or []
        if not mitigation_steps and "mitigated_kql" in parsed:
            mkql = parsed.get("mitigated_kql")
            if isinstance(mkql, list):
                mitigation_steps = [str(k) for k in mkql]
            elif mkql:
                mitigation_steps = [str(mkql)]
        elif not isinstance(mitigation_steps, list):
            mitigation_steps = [str(mitigation_steps)]
        mitigation_steps = [str(s).strip() for s in mitigation_steps if str(s).strip()]

        if noise_source == "Unknown Noise Source" and not affected_entities and not mitigation_steps:
            logger.error(f"Diagnostics pipeline failed: could not extract noise diagnostics from raw output:\n{raw_response}")
            return None

        return {
            "noise_source": noise_source,
            "affected_entities": affected_entities,
            "mitigation_steps": mitigation_steps,
        }
    except Exception as e:
        logger.error(f"Diagnostics pipeline failed: {e}", exc_info=True)
        return None


# Ensure SentinelClient has execute_query
if not hasattr(SentinelClient, "execute_query"):
    def _execute_query_fn(self, query_text: str, timespan_days: int = 7) -> Dict[str, Any]:
        result = self.execute_kql_query(query_text=query_text, timespan_days=timespan_days)
        row_count = result.get("row_count", 0)
        sample_records = result.get("sample_records") or result.get("records") or result.get("events")
        if not sample_records and result.get("tables"):
            tables = result.get("tables", [])
            if tables and isinstance(tables, list) and len(tables) > 0:
                primary_table = tables[0]
                if isinstance(primary_table, dict):
                    columns = [col.get("name") if isinstance(col, dict) else str(col) for col in primary_table.get("columns", [])]
                    rows = primary_table.get("rows", [])
                    extracted = []
                    for row in rows[:20]:
                        if isinstance(row, list) and columns:
                            extracted.append(dict(zip(columns, row)))
                        elif isinstance(row, dict):
                            extracted.append(row)
                    if extracted:
                        sample_records = extracted
        if not sample_records:
            sample_records = []
        return {
            "success": True,
            "row_count": row_count,
            "sample_records": sample_records,
            "records": sample_records,
            "events": sample_records,
            "timespan_days": timespan_days,
            "query": query_text,
        }
    SentinelClient.execute_query = _execute_query_fn

try:
    import backend.telemetry_tuner as telemetry_tuner_mod
    telemetry_tuner_mod.diagnose_telemetry_noise = diagnose_telemetry_noise
except Exception:
    pass


@app.post("/api/telemetry/tune")
async def tune_telemetry(
    payload: TuneRequest,
    authorization: Optional[str] = Header(None),
    current_user: Optional[str] = Depends(get_current_user) if HAS_FASTAPI else None,
):
    """
    POST /api/telemetry/tune
    Accepts raw_kql and current_threshold, queries Sentinel historical baselines,
    computes dynamic threshold recommendations, and analyzes sample records with Gemini.
    Protected with JWT Bearer authentication.
    """
    user = current_user or await get_current_user(authorization=authorization)

    kql_query = getattr(payload, "raw_kql", None) or (payload.get("raw_kql") if isinstance(payload, dict) else "")
    current_threshold = getattr(payload, "current_threshold", None)
    if current_threshold is None and isinstance(payload, dict):
        current_threshold = payload.get("current_threshold", 1)
    if current_threshold is None:
        current_threshold = 1

    # Retrieve Sentinel credentials from vault or integration registry
    vault = VaultService()
    sentinel_creds = ACTIVE_INTEGRATIONS.get("sentinel", {})
    tenant_id = sentinel_creds.get("tenant_id") or vault.get_secret("AZURE_TENANT_ID") or os.environ.get("AZURE_TENANT_ID", "")
    client_id = sentinel_creds.get("client_id") or vault.get_secret("AZURE_CLIENT_ID") or os.environ.get("AZURE_CLIENT_ID", "")
    client_secret = sentinel_creds.get("client_secret") or vault.get_secret("AZURE_CLIENT_SECRET") or os.environ.get("AZURE_CLIENT_SECRET", "")
    workspace_id = sentinel_creds.get("workspace_id") or vault.get_secret("SENTINEL_WORKSPACE_ID") or os.environ.get("SENTINEL_WORKSPACE_ID", "")

    sentinel_client = SentinelClient(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
        workspace_id=workspace_id,
    )

    try:
        if hasattr(sentinel_client, "execute_query"):
            sentinel_res = sentinel_client.execute_query(kql_query)
        else:
            sentinel_res = sentinel_client.execute_kql_query(kql_query)
    except Exception as e:
        logger.error(f"Diagnostics pipeline failed: Sentinel query execution error: {e}", exc_info=True)
        sentinel_res = {"row_count": 0, "sample_records": []}

    if isinstance(sentinel_res, dict):
        baseline_count = sentinel_res.get("row_count", sentinel_res.get("count", 0))
        sample_records = sentinel_res.get("sample_records") or sentinel_res.get("records") or sentinel_res.get("events") or []
        if not sample_records and sentinel_res.get("tables"):
            tables = sentinel_res.get("tables", [])
            if tables and isinstance(tables, list) and len(tables) > 0:
                primary_table = tables[0]
                if isinstance(primary_table, dict):
                    columns = [col.get("name") if isinstance(col, dict) else str(col) for col in primary_table.get("columns", [])]
                    rows = primary_table.get("rows", [])
                    for row in rows[:10]:
                        if isinstance(row, list) and columns:
                            sample_records.append(dict(zip(columns, row)))
                        elif isinstance(row, dict):
                            sample_records.append(row)
    elif isinstance(sentinel_res, (int, float)):
        baseline_count = int(sentinel_res)
        sample_records = []
    elif isinstance(sentinel_res, (list, tuple)):
        baseline_count = len(sentinel_res)
        sample_records = list(sentinel_res[:10])
    else:
        baseline_count = 0
        sample_records = []

    # Calculate dynamic threshold
    tuning_calc = calculate_dynamic_threshold(
        baseline_event_count=baseline_count,
        static_rule_threshold=current_threshold,
    )
    original_threshold = tuning_calc.get("original_threshold", current_threshold)
    suggested_threshold = tuning_calc.get("suggested_threshold", current_threshold)
    tuning_rationale = tuning_calc.get("tuning_rationale", "")

    # LLM noise diagnostics
    noise_diagnostics = None
    if sample_records and len(sample_records) > 0:
        try:
            # Case-insensitive resolution from vault, fallback to env
            gemini_key = None
            for candidate_key in ("GEMINI_API_KEY", "gemini_api_key", "Gemini_API_Key", "gemini_key", "GEMINI_KEY"):
                try:
                    val = vault.get_secret(candidate_key)
                    if val and val.strip():
                        gemini_key = val.strip()
                        break
                except Exception as lookup_err:
                    logger.debug(f"Vault secret lookup for '{candidate_key}' failed: {lookup_err}")

            if not gemini_key:
                gemini_key = (
                    os.getenv("GEMINI_API_KEY")
                    or os.getenv("gemini_api_key")
                    or os.getenv("GEMINI_KEY")
                    or os.getenv("gemini_key")
                    or ""
                ).strip()

            if gemini_key:
                logger.debug(f"Found Gemini API key with length: {len(gemini_key)}")
            else:
                logger.debug("No Gemini API key found in vault or environment")

            llm_client = get_llm_client(provider="gemini", api_key=gemini_key)
            if llm_client:
                noise_diagnostics = await diagnose_telemetry_noise(
                    raw_kql=kql_query,
                    sample_records=sample_records,
                    llm_client=llm_client,
                )
            else:
                logger.error("Diagnostics pipeline failed: get_llm_client returned None for provider 'gemini'")
        except Exception as e:
            logger.error(f"Diagnostics pipeline failed: {e}", exc_info=True)
            noise_diagnostics = None
    else:
        logger.warning(
            f"Diagnostics pipeline skipped: sample_records is empty ({baseline_count} events). "
            f"kql_query: {kql_query[:150]}"
        )

    tuned_kql = None
    if noise_diagnostics:
        affected_entities = getattr(noise_diagnostics, "affected_entities", None)
        if affected_entities is None and isinstance(noise_diagnostics, dict):
            affected_entities = noise_diagnostics.get("affected_entities")
        if affected_entities:
            try:
                target_field = "Computer"
                has_account_field = bool(re.search(r"\bAccountName\b", kql_query, re.IGNORECASE))
                looks_like_account = any(
                    re.search(r"^(?:svc[-_]|adm[-_]|user[-_]|service|admin|[a-z0-9._%+-]+@|[a-z0-9._-]+\\)", str(e), re.IGNORECASE)
                    for e in affected_entities
                )
                if has_account_field and (looks_like_account or not re.search(r"\bComputer\b", kql_query, re.IGNORECASE)):
                    target_field = "AccountName"

                tuned_kql = apply_exclusions(raw_kql=kql_query, entities=affected_entities, target_field=target_field)
            except Exception as e:
                logger.error(f"Diagnostics pipeline failed: apply_exclusions error: {e}", exc_info=True)
                tuned_kql = None

    return {
        "original_threshold": int(original_threshold),
        "suggested_threshold": int(suggested_threshold),
        "tuning_rationale": str(tuning_rationale),
        "noise_diagnostics": noise_diagnostics,
        "tuned_kql": tuned_kql,
    }

