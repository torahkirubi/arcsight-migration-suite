# ArcSight Migration Suite

> **An AI-powered SIEM engineering tool that autonomously translates legacy ArcSight XML rules into optimized Splunk SPL and Microsoft Sentinel KQL.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg)](https://fastapi.tiangolo.com)
[![React 18](https://img.shields.io/badge/React-18.2-61DAFB.svg)](https://react.dev/)
[![TailwindCSS](https://img.shields.io/badge/Tailwind_CSS-3.4-38B2AC.svg)](https://tailwindcss.com/)
[![Splunk Enterprise](https://img.shields.io/badge/Splunk-Enterprise_9.x-black.svg)](https://www.splunk.com/)
[![Docker Compose](https://img.shields.io/badge/Docker_Compose-Ready-2496ED.svg)](https://www.docker.com/)

---

## Overview

Migrating legacy SIEM detection rules from Micro Focus / OpenText ArcSight ESM to modern cloud data platforms is fraught with operational challenges:
- **Obscure Vendor Fields**: Legacy custom strings (`deviceCustomString1`, `attackerServiceName`, `deviceProcessName`) must map accurately to Microsoft Defender XDR (`ProcessCommandLine`, `FileName`, `AccountName`) and Splunk CIM schemas (`CommandLine`, `process_name`, `user`, `dest`).
- **Complex Boolean Logic & Malformed Exports**: ArcSight XML/HTML documentation exports frequently contain nested parenthetical groups, truncated clauses, and duplicated terms across multiple fields.
- **Silent Exclusion Inversion**: Conventional LLM prompting regularly drops negative filters (`!Contains`, `NE`, `!=`), converting strict exclusions into inclusive matches—triggering false-positive storms and SOC alert fatigue.

The **ArcSight Migration Suite** solves this by uniting **deterministic parsing and regex auditing** with an **autonomous LLM self-correction loop**. It transforms messy ArcSight correlation logic into clean, production-grade KQL and SPL queries, rigorously validates them against a live Splunk REST API, and delivers complete detection engineering runbooks mapped to MITRE ATT&CK tactics.

---

## Architecture & Workflow

```
 ┌────────────────────────────────────────────────────────┐
 │            Legacy ArcSight ESM Rule Export             │
 │         (XML / HTML Rule Definition & Metadata)        │
 └───────────────────────────┬────────────────────────────┘
                             │
                             ▼
 ┌────────────────────────────────────────────────────────┐
 │        Deterministic Parser (backend/arcsight_parser)  │
 │  - Zero-LLM Extraction: Rule Name, Frequency, Group By │
 │  - Verbatim MITRE Tactic from Stage Annotation         │
 │  - Required Terms & Infix/Prefix Exclusion Extraction  │
 └───────────────────────────┬────────────────────────────┘
                             │
                             ▼
 ┌────────────────────────────────────────────────────────┐
 │           LLM Translation Engine (Dual-Target)         │
 │          Microsoft Defender KQL & Splunk SPL           │
 └───────────────────────────┬────────────────────────────┘
                             │
                             ▼
 ┌────────────────────────────────────────────────────────┐
 │          Deep Mode Autonomous Self-Correction          │
 │                                                        │
 │     ┌──────────────┐             ┌─────────────────┐   │
 │     │  Draft SPL   │ ──(REST)──► │ Splunk Engine   │   │
 │     │  Generation  │ ◄─(Errors)─ │ (REST API :8089)│   │
 │     └──────────────┘             └─────────────────┘   │
 │               Iterative feedback loop (up to 3x)       │
 └───────────────────────────┬────────────────────────────┘
                             │
                             ▼
 ┌────────────────────────────────────────────────────────┐
 │      Deterministic Logic Auditing (Zero-LLM)           │
 │  - Guarantees 100% exclusion retention (!=, NOT, !in)  │
 │  - Flags dropped filters and false-positive risks      │
 └───────────────────────────┬────────────────────────────┘
                             │
                             ▼
 ┌────────────────────────────────────────────────────────┐
 │        Data-Dense SOC Dashboard & Git Export           │
 │  - Real-Time SSE Terminal Status Logs                  │
 │  - Live Bounded Splunk Oneshot Search (Mock Sysmon)    │
 │  - Detection Runbooks & Version-Controlled Artifacts   │
 └────────────────────────────────────────────────────────┘
```

---

## Key Features

### 1. Deep Mode Autonomous Loop
- **Autonomous Iterative Self-Correction**: When Deep Mode is toggled, draft SPL queries are immediately executed against a live Splunk instance via its management REST API (`/services/search/jobs/export` with `exec_mode=oneshot`).
- **Syntax Error Feedback**: If Splunk rejects the query (e.g., mismatched quotes, illegal pipe order, or unknown eval functions), the exact parser error message is fed back to the LLM (powered by Google Gemini 1.5 Flash or local models via LM Studio) in an automated retry loop.
- **Real-Time Streaming Status**: Powered by Server-Sent Events (SSE), the UI renders a monospace terminal log showing each execution attempt, parser error, rewrite stage, and deterministic validation step in real time.

### 2. Deterministic Logic Auditing
- **Zero-LLM Exclusion Guarantee**: An independent Python regex validation engine (`translation_validator.py` + `arcsight_parser.py`) extracts all required tokens and exclusion predicates (`!Contains`, `NE`, `!=`, `doesNotContain`, `!in`).
- **Prevention of SOC Alert Fatigue**: Validates that generated KQL and SPL queries explicitly negate every excluded entity (`NOT (...)`, `!=`, `not in()`, `!has`). Any query dropping an exclusion is flagged immediately with a 0% coverage score and comprehensive audit report before reaching production.
- **Strict SPL Syntax Directives**: Enforces Splunk best practices:
  - *Wildcard Filtering*: Mandates `| search Field IN (...)` over `| where` (avoiding Splunk treating `*` as a literal).
  - *Time Index Pruning*: Prevents runtime `| where _time >= relative_time(...)` calculations in favor of native index windowing (`earliest=-1m`).

### 3. Live Data Validation
- **Interactive UI Testing Modal**: Test translated SPL directly from the dashboard against a local Splunk Enterprise container pre-populated with mock Windows Event Logs (Sysmon / Event ID 1 Process Creation).
- **Safe & Bounded Execution**: Queries run as strictly read-only oneshot search jobs with configurable time boundaries (`earliest`, `latest`) and event limits, completely isolated from alert scheduling or index modification.
- **Instant Result Inspection**: Displays raw JSON event payloads, execution latency, and match counts to verify detection efficacy before deployment.

### 4. Comprehensive Detection Runbooks
- **Automated Triage Playbooks**: Generates incident response runbooks with initial investigation questions, containment steps, and escalation criteria.
- **MITRE ATT&CK Attribution**: Directly reflects the verified MITRE tactic annotated within the ArcSight rule definition.
- **Human-in-the-Loop MDE Assessment**: Enforces strict operational boundaries—distinguishing between verified rule translation and human SOC analyst verification of Microsoft Defender native coverage.

### 5. Git-Ready Export & SQLite Audit Store
- **Version Control Export**: Organizes translations into an enterprise-ready directory structure (`.kql`, `.spl`, and `.md` runbook files).
- **Historical Audit Trail**: Persists all translation jobs, raw inputs, generated queries, validation verdicts, and human coverage assessments in SQLite (`audit_history.db`).

---

## Tech Stack

| Domain | Technology | Description |
|---|---|---|
| **Frontend** | **React 18** | High-performance component architecture |
| | **TailwindCSS 3.4** | Utility-first styling adhering to `DESIGN.md` (Data-Dense Dashboard) |
| | **Vite 5** | Fast HMR and production bundle optimization |
| | **Lucide React** | Clean, technical iconography |
| | **TanStack Query** | Asynchronous state management and caching |
| **Backend** | **Python 3.11+** | Core runtime for parsing and detection logic |
| | **FastAPI** | High-performance asynchronous REST API & SSE streaming |
| | **Uvicorn** | Asynchronous ASGI server |
| | **SQLite** | Local persistence for translation audit logs |
| | **HTTPX** | Asynchronous HTTP client for LLM and Splunk REST communication |
| **Validation** | **Splunk Enterprise** | Official Splunk container running on port 8089 (REST) & 8000 (Web) |
| | **Mock Sysmon Logs** | Windows Event Logs for testing process creation and command-line execution |
| **AI / LLM** | **Google Gemini 1.5 Flash** | Cloud LLM provider for rapid query generation and self-correction |
| | **LM Studio / Ollama** | Optional local OpenAI-compatible LLM execution for sensitive air-gapped environments |
| **Infrastructure**| **Docker & Docker Compose** | Multi-container orchestration (`splunk`, `backend`, `frontend`) |

---

## UI Design System (`DESIGN.md`)

The application interface is intentionally crafted as a **Data-Dense SOC Dashboard**:
- **Palette**: Deep slate dark mode (`slate-950` backgrounds, `slate-900` surfaces, `slate-800` borders).
- **Semantics**: Stark `cyan-500` for primary actions, crisp `emerald-500` for passing validations, and `rose-500` for syntax failures.
- **Typography**: `IBM Plex Sans` for UI labels paired with `JetBrains Mono` for code blocks, queries, and terminal logs.
- **Zero Distractions**: Sharp edges (`rounded-none` / `rounded-sm`), 1px borders, zero bouncy animations, and dense information layout.

---

## Getting Started

### Prerequisites
- [Docker](https://docs.docker.com/get-docker/) & [Docker Compose](https://docs.docker.com/compose/)
- *(Optional for bare-metal run)*: Python 3.11+, Node.js 18+

### 1. Environment Configuration
Create a `.env` file in the root directory (this file is excluded from Git):
```bash
# LLM Configuration
# For Google Gemini (via OpenAI-compatible endpoint or OpenRouter):
OPENAI_API_KEY=your_gemini_api_key_here
OPENAI_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai/

# Or for local air-gapped models via LM Studio:
LM_STUDIO_BASE_URL=http://host.docker.internal:1234/v1
DEFAULT_LLM_MODEL=qwen2.5-coder-7b-instruct

# Splunk Enterprise Configuration
SPLUNK_HOST=https://splunk:8089
SPLUNK_USER=admin
SPLUNK_PASSWORD=ChangeMe123!
```

### 2. Launch with Docker Compose
Start all services (Splunk Enterprise, FastAPI Backend, and React Frontend) with a single command:
```bash
docker compose up --build -d
```

Service endpoints:
- **Frontend Dashboard**: [http://localhost:3000](http://localhost:3000)
- **Backend API Docs**: [http://localhost:8001/docs](http://localhost:8001/docs)
- **Splunk Enterprise Web UI**: [http://localhost:8000](http://localhost:8000) *(admin / ChangeMe123!)*
- **Splunk REST API**: [https://localhost:8089](https://localhost:8089)

---

## Manual Local Development Setup

If running without Docker:

### 1. Backend (FastAPI)
```bash
# Navigate to backend and create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r backend/requirements.txt

# Run the FastAPI server
uvicorn backend.app:app --host 0.0.0.0 --port 8001 --reload
```

### 2. Frontend (React + Vite)
```bash
# Navigate to frontend and install dependencies
cd frontend
npm install

# Start Vite development server
npm run dev
```
The frontend will start at `http://localhost:5173`.

---

## Automated Test Suite

The project includes an extensive unit test suite covering deterministic parsing, exclusion extraction, prompt directives, Splunk API sanitization, and audit stores.

Execute the test suite with:
```bash
python3 -m unittest discover -s backend/tests
```

Example test output:
```text
.............................................
----------------------------------------------------------------------
Ran 45 tests in 0.385s

OK
```

---

## Security & Operational Safety

- **Read-Only Splunk Operations**: All queries executed against Splunk use read-only oneshot search jobs (`exec_mode=oneshot`). The backend never creates, modifies, or deletes indexes, alerts, or configurations.
- **Query Sanitization**: LLM output is aggressively sanitized to strip accidental Markdown fences (````spl`, ````kql`, ````) and stray tickmarks before dispatch to Splunk, while preserving legitimate Splunk macro backticks.
- **Air-Gapped Ready**: The backend supports fully offline LLM deployments (via LM Studio, Ollama, or vLLM) so proprietary detection IP and logs never leave internal networks.

---

## License

This project is licensed under the [MIT License](LICENSE).

