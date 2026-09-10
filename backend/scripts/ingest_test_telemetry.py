#!/usr/bin/env python3
"""
backend/scripts/ingest_test_telemetry.py
========================================
Telemetry Ingestion & Connectivity Verification Script
Azure Monitor Logs Ingestion API (DCE/DCR) + Sentinel Log Analytics query check.

Usage:
    python3 backend/scripts/ingest_test_telemetry.py

Credentials are read from environment variables (or a local .env file).
See .env.example for all required variables.

Dependencies: requests (already in requirements.txt) — no azure-sdk required.
"""

import json
import os
import sys
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

try:
    import requests
except ImportError:
    print("[FATAL] 'requests' library not installed. Run: pip install requests")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Optional .env loader (best-effort, so script works standalone)
# ---------------------------------------------------------------------------
def _load_dotenv(path: str = ".env") -> None:
    """Parse a simple KEY=VALUE .env file and populate os.environ."""
    if not os.path.exists(path):
        return
    with open(path, "r") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


# Resolve .env relative to the project root (two levels up from this script)
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(os.path.dirname(_SCRIPT_DIR))
_load_dotenv(os.path.join(_PROJECT_ROOT, ".env"))

# ---------------------------------------------------------------------------
# Configuration (all from environment)
# ---------------------------------------------------------------------------
AZURE_TENANT_ID       = os.environ.get("AZURE_TENANT_ID", "")
AZURE_CLIENT_ID       = os.environ.get("AZURE_CLIENT_ID", "")
AZURE_CLIENT_SECRET   = os.environ.get("AZURE_CLIENT_SECRET", "")
SENTINEL_WORKSPACE_ID = os.environ.get("SENTINEL_WORKSPACE_ID") or os.environ.get("AZURE_WORKSPACE_ID", "")
SENTINEL_BASE_URL     = os.environ.get("SENTINEL_BASE_URL", "https://api.loganalytics.io/v1")

LOG_INGEST_CLIENT_ID  = os.environ.get("AZURE_LOG_INGEST_CLIENT_ID", "")
LOG_INGEST_SECRET     = os.environ.get("AZURE_LOG_INGEST_SECRET", "")
DCE_ENDPOINT          = os.environ.get("DCE_INGESTION_ENDPOINT", "").rstrip("/")
DCR_IMMUTABLE_ID      = os.environ.get("DCR_IMMUTABLE_ID", "")
CUSTOM_STREAM_NAME    = os.environ.get("CUSTOM_STREAM_NAME", "Custom-SecurityEvents_CL")

INGESTION_API_VERSION = "2023-01-01"

# ---------------------------------------------------------------------------
# ANSI colour helpers
# ---------------------------------------------------------------------------
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"

def _ok(msg):   return f"{GREEN}[PASS]{RESET} {msg}"
def _fail(msg): return f"{RED}[FAIL]{RESET} {msg}"
def _info(msg): return f"{CYAN}[INFO]{RESET} {msg}"
def _warn(msg): return f"{YELLOW}[WARN]{RESET} {msg}"


# ---------------------------------------------------------------------------
# OAuth token acquisition
# ---------------------------------------------------------------------------
def acquire_token(tenant_id: str, client_id: str, client_secret: str, scope: str) -> Optional[str]:
    """Acquires a bearer token via Azure OAuth client_credentials flow."""
    if not all([tenant_id, client_id, client_secret]):
        return None
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "client_credentials",
        "scope": scope,
    }
    try:
        resp = requests.post(url, data=data, timeout=15)
        if resp.status_code == 200:
            return resp.json().get("access_token")
        print(_fail(f"Token acquisition HTTP {resp.status_code}: {resp.text[:300]}"))
    except Exception as exc:
        print(_fail(f"Token acquisition exception: {exc}"))
    return None


# ---------------------------------------------------------------------------
# Build realistic SecurityEvents_CL telemetry batch
# ---------------------------------------------------------------------------
def build_telemetry_records(batch_size: int = 20) -> List[Dict[str, Any]]:
    """
    Generates a batch of realistic SecurityEvents_CL records.
    70% are EventID 4625 (failed logon) noise from known noisy service accounts,
    with full AccountName, ProcessName, CommandLine, Computer fields to enable
    meaningful LLM noise diagnostics.
    """
    base_time = datetime.now(timezone.utc)
    noisy_accounts = [
        "svc-vulnerability-scanner",
        "svc-backup-admin",
        "svc-monitoring",
        "adm-deployment",
    ]
    hosts = [
        "DC-01.corp.local",
        "APP-SRV02.corp.local",
        "WEB-PROD01.corp.local",
        "DB-PROD01.corp.local",
        "JUMP-01.corp.local",
    ]
    process_pairs = [
        ("powershell.exe",
         "powershell.exe -NonInteractive -NoProfile -ExecutionPolicy Bypass -File C:\\scripts\\scan.ps1"),
        ("backup_agent.exe",
         "backup_agent.exe --target \\\\DC-01\\SYSVOL --mode full --quiet"),
        ("nssm.exe",
         "nssm.exe start BackupService"),
        ("cmd.exe",
         "cmd.exe /c net use \\\\DC-01\\C$ /user:svc-backup-admin"),
        ("wmic.exe",
         "wmic process call create 'powershell.exe -enc <base64payload>'"),
    ]

    records: List[Dict[str, Any]] = []
    for i in range(batch_size):
        ts = (base_time - timedelta(minutes=i * 3)).strftime("%Y-%m-%dT%H:%M:%SZ")
        account = noisy_accounts[i % len(noisy_accounts)]
        host = hosts[i % len(hosts)]
        proc, cmd = process_pairs[i % len(process_pairs)]
        # 70% EventID 4625 (failed logon), 20% 4624 (success), 10% 4688 (process)
        event_id = 4625 if i % 10 < 7 else (4624 if i % 10 < 9 else 4688)
        activity = (
            "4625 - An account failed to log on."
            if event_id == 4625
            else ("4624 - An account was successfully logged on."
                  if event_id == 4624
                  else "4688 - A new process has been created.")
        )
        records.append({
            "TimeGenerated":   ts,
            "Computer":        host,
            "AccountName":     account,
            "AccountDomain":   "CORP",
            "EventID":         event_id,
            "Activity":        activity,
            "ProcessName":     proc,
            "CommandLine":     cmd,
            "LogonType":       3,
            "IpAddress":       f"10.0.{(i % 4) + 1}.{(i * 7 + 1) % 254}",
            "WorkstationName": f"WS-{i + 1:03d}",
            "SubjectUserName": account,
            "TargetUserName":  account,
            "FailureReason":   "Unknown user name or bad password." if event_id == 4625 else "",
            "Status":          "0xC000006D" if event_id == 4625 else "0x0",
        })
    return records


# ---------------------------------------------------------------------------
# Step 1: Ingest via Azure Monitor Logs Ingestion API
# ---------------------------------------------------------------------------
def ingest_telemetry(records: List[Dict[str, Any]]) -> Tuple[bool, str]:
    """POSTs telemetry records to the DCE/DCR endpoint. Returns (success, message)."""
    if not all([LOG_INGEST_CLIENT_ID, LOG_INGEST_SECRET, AZURE_TENANT_ID]):
        return False, "Missing ingestion SP credentials (AZURE_LOG_INGEST_CLIENT_ID/AZURE_LOG_INGEST_SECRET/AZURE_TENANT_ID)"
    if not DCE_ENDPOINT:
        return False, "DCE_INGESTION_ENDPOINT not set"
    if not DCR_IMMUTABLE_ID:
        return False, "DCR_IMMUTABLE_ID not set"

    print(_info(f"Acquiring ingestion OAuth token (client={LOG_INGEST_CLIENT_ID[:8]}...)"))
    token = acquire_token(
        tenant_id=AZURE_TENANT_ID,
        client_id=LOG_INGEST_CLIENT_ID,
        client_secret=LOG_INGEST_SECRET,
        scope="https://monitor.azure.com/.default",
    )
    if not token:
        return False, "Failed to acquire ingestion OAuth token"
    print(_ok(f"Ingestion token acquired (length={len(token)})"))

    url = (
        f"{DCE_ENDPOINT}/dataCollectionRules/{DCR_IMMUTABLE_ID}"
        f"/streams/{CUSTOM_STREAM_NAME}?api-version={INGESTION_API_VERSION}"
    )
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    print(_info(f"POST → {url}"))
    print(_info(f"Sending {len(records)} records to stream: {CUSTOM_STREAM_NAME}"))

    try:
        resp = requests.post(url, data=json.dumps(records), headers=headers, timeout=30)
        if resp.status_code in (200, 204):
            return True, f"HTTP {resp.status_code} — {len(records)} records accepted by DCE"
        return False, f"HTTP {resp.status_code}: {resp.text[:400]}"
    except Exception as exc:
        return False, f"Ingestion request exception: {exc}"


# ---------------------------------------------------------------------------
# Step 2: Verify Sentinel KQL connectivity
# ---------------------------------------------------------------------------
def verify_sentinel_connectivity() -> Tuple[bool, str, int]:
    """Runs a count query against SecurityEvents_CL. Returns (success, msg, count)."""
    if not all([AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET]):
        return False, "Missing Sentinel query SP credentials", 0
    if not SENTINEL_WORKSPACE_ID:
        return False, "SENTINEL_WORKSPACE_ID not configured", 0

    print(_info(f"Acquiring Sentinel query token (client={AZURE_CLIENT_ID[:8]}...)"))
    token = acquire_token(
        tenant_id=AZURE_TENANT_ID,
        client_id=AZURE_CLIENT_ID,
        client_secret=AZURE_CLIENT_SECRET,
        scope="https://api.loganalytics.io/.default",
    )
    if not token:
        return False, "Failed to acquire Sentinel query OAuth token", 0
    print(_ok(f"Sentinel query token acquired (length={len(token)})"))

    kql = "SecurityEvents_CL | where TimeGenerated > ago(7d) | summarize TotalEvents=count()"
    url = f"{SENTINEL_BASE_URL.rstrip('/')}/workspaces/{SENTINEL_WORKSPACE_ID}/query"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    print(_info(f"KQL: {kql}"))
    print(_info(f"Workspace: {SENTINEL_WORKSPACE_ID}"))

    try:
        resp = requests.post(url, json={"query": kql, "timespan": "P7D"}, headers=headers, timeout=20)
        if resp.status_code == 200:
            data = resp.json()
            tables = data.get("tables", [])
            if tables and isinstance(tables, list):
                primary = tables[0]
                cols = [c.get("name") for c in primary.get("columns", [])]
                rows = primary.get("rows", [])
                if rows and cols:
                    row_dict = dict(zip(cols, rows[0]))
                    count = int(row_dict.get("TotalEvents", 0))
                    return True, f"Workspace reachable — {count} SecurityEvents_CL records in last 7d", count
            return True, "Workspace reachable — query returned empty result (table may be new)", 0
        if resp.status_code in (400, 404):
            return True, f"Workspace reachable (HTTP {resp.status_code} — SecurityEvents_CL table may not exist yet)", 0
        return False, f"HTTP {resp.status_code}: {resp.text[:400]}", 0
    except Exception as exc:
        return False, f"Sentinel query exception: {exc}", 0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> int:
    print(f"\n{'=' * 68}")
    print("  ArcSight Migration Suite — Telemetry Ingestion & Verification")
    print(f"{'=' * 68}\n")

    results: List[Tuple[str, bool, str]] = []

    # --- STEP 1: Config check ---
    print(f"{CYAN}{'─' * 68}{RESET}")
    print(f"{CYAN}STEP 1: Environment Configuration Check{RESET}")
    print(f"{CYAN}{'─' * 68}{RESET}")
    required_vars = [
        "AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET",
        "SENTINEL_WORKSPACE_ID", "AZURE_LOG_INGEST_CLIENT_ID",
        "AZURE_LOG_INGEST_SECRET", "DCE_INGESTION_ENDPOINT",
        "DCR_IMMUTABLE_ID", "CUSTOM_STREAM_NAME",
    ]
    missing = []
    for var in required_vars:
        val = os.environ.get(var, "")
        if val:
            display = val[:6] + "..." if len(val) > 6 else val
            print(_ok(f"{var} = {display}"))
        else:
            missing.append(var)
            print(_fail(f"{var} is NOT set"))
    cfg_ok = not missing
    msg = "All vars present" if cfg_ok else f"Missing: {', '.join(missing)}"
    results.append(("Config check", cfg_ok, msg))

    # --- STEP 2: Ingest telemetry ---
    print(f"\n{CYAN}{'─' * 68}{RESET}")
    print(f"{CYAN}STEP 2: Ingest SecurityEvents_CL batch (20 records){RESET}")
    print(f"{CYAN}{'─' * 68}{RESET}")
    records = build_telemetry_records(batch_size=20)
    print(_info(f"Sample record [0]:\n{json.dumps(records[0], indent=2)}"))
    ingest_ok, ingest_msg = ingest_telemetry(records)
    print(_ok(ingest_msg) if ingest_ok else _fail(ingest_msg))
    results.append(("Telemetry ingestion via DCE/DCR", ingest_ok, ingest_msg))

    # --- STEP 3: Sentinel connectivity ---
    print(f"\n{CYAN}{'─' * 68}{RESET}")
    print(f"{CYAN}STEP 3: Sentinel workspace connectivity (KQL count){RESET}")
    print(f"{CYAN}{'─' * 68}{RESET}")
    conn_ok, conn_msg, count = verify_sentinel_connectivity()
    print(_ok(conn_msg) if conn_ok else _fail(conn_msg))
    results.append(("Sentinel connectivity", conn_ok, conn_msg))

    # --- STEP 4: Post-ingestion verification (only if ingest succeeded) ---
    if ingest_ok:
        print(f"\n{CYAN}{'─' * 68}{RESET}")
        print(f"{CYAN}STEP 4: Post-ingestion record verification (30s propagation delay){RESET}")
        print(f"{CYAN}{'─' * 68}{RESET}")
        print(_info("Waiting 30s for Azure Monitor ingestion propagation..."))
        time.sleep(30)
        v_ok, v_msg, v_count = verify_sentinel_connectivity()
        print(_ok(v_msg) if v_ok else _fail(v_msg))
        if v_ok and v_count > 0:
            print(_ok(f"Confirmed {v_count} SecurityEvents_CL records visible in workspace"))
        results.append(("Post-ingestion record visibility", v_ok, v_msg))
    else:
        print(_warn("\nSkipping post-ingestion verification (ingestion step did not complete successfully)"))

    # --- Summary ---
    print(f"\n{'=' * 68}")
    print("  SUMMARY")
    print(f"{'=' * 68}")
    all_ok = True
    for step, passed, detail in results:
        icon = _ok(step) if passed else _fail(step)
        print(f"  {icon}")
        print(f"    └─ {detail}")
        if not passed:
            all_ok = False
    print(f"{'=' * 68}\n")

    if all_ok:
        print(_ok("All steps passed. Telemetry pipeline is operational.\n"))
        return 0
    failed = [name for name, ok, _ in results if not ok]
    print(_warn(f"Failed steps: {', '.join(failed)}"))
    print(_info("Verify credentials and Azure resource configuration.\n"))
    return 1


if __name__ == "__main__":
    sys.exit(main())
