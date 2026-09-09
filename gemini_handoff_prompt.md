# ArcSight Migration Suite — Handoff Brief for Frontend Rebuild

## Read this whole document first. At the end, before writing any code,
## summarize back your understanding of the architecture and the plan
## you intend to follow, so we can confirm alignment before you start.

---

## 1. What we're trying to achieve

This is a SOC (Security Operations Center) detection-engineering tool that
migrates legacy ArcSight ESM correlation rules to modern SIEM platforms —
specifically Microsoft Defender XDR (KQL) and Splunk (SPL) — using a
locally-run LLM (Qwen2.5 Coder, served via LM Studio) instead of a cloud
API, for data-sensitivity reasons.

The core insight driving the architecture: **anything that can be
extracted deterministically from the source rule should be, rather than
asked of the LLM.** A local 7B/14B model is good at translation and
reasoning over data already in front of it, but unreliable at precise
syntax rules and has zero ability to know current, real-world facts (like
whether Microsoft's product already covers a given technique). The system
is built to route each sub-task to whichever is actually reliable for it —
deterministic parsing, the LLM, pySigma's real compiler, or a human.

There are two parallel pipelines:

1. **Legacy path (ArcSight → Sigma → KQL/SPL):** translates a rule into
   Sigma YAML first, validates it compiles via pySigma, then converts
   Sigma to KQL/SPL. Useful when Sigma-format output itself is wanted.
2. **Direct path (ArcSight → KQL/SPL, no Sigma):** skips Sigma entirely.
   This is the primary/newer path and where most current work is focused.

## 2. How the backend works (FastAPI, `app.py` + `backend/`)

### Deterministic extraction — `backend/arcsight_parser.py`
`parse_arcsight_rule(raw_text)` takes a raw ArcSight ESM rule export (messy
HTML/XML rule-documentation format) and extracts, via regex — **with zero
LLM involvement**:
- Rule name (from `SetEventField(name, ...)`)
- Priority → severity mapping (ArcSight priority 0-10 → Low/Medium/High/Critical)
- Frequency ("Matching N events in M Minutes")
- Grouped-by fields
- **MITRE ATT&CK tactic** — ArcSight stores this directly in
  `SetEventField(eventAnnotationStage, <Resource URI="/All Stages/MITRE Tactics/Discovery".../>)`.
  This is pulled out verbatim, not guessed. `mitre_source` tracks whether
  it was actually found ("extracted from rule") vs. absent.
- The raw boolean condition logic (the `Contains()/EQ()/And/Or` expression)
  is left for the LLM — this is the one part that genuinely needs
  translation, not extraction.

This module has been hardened against a real data-quality issue: ArcSight
exports sometimes drop a closing parenthesis per clause. Extraction uses
`And`/`Or` keyword boundaries rather than paren-balancing, since
paren-counting cascades badly on malformed input.

### LLM translation — `backend/gemma_client.py` + `backend/direct_translate_prompts.py`
`GemmaLocalClient` wraps LM Studio's OpenAI-compatible `/v1/chat/completions`
endpoint. Base URL is configurable via the `LM_STUDIO_BASE_URL` env var
(defaults to `http://localhost:1234/v1`; in Docker this must point to
`http://host.docker.internal:1234/v1` since LM Studio runs on the host,
not in a container). It raises a clear `RuntimeError` on connection
failure or response truncation (`finish_reason == "length"`) — **note:**
this RuntimeError is not yet caught inside every endpoint that calls it,
so a down LM Studio currently surfaces as a raw 500 in some paths; this is
a known, not-yet-fixed rough edge.

`DIRECT_TRANSLATE_PROMPT` gives the model the ArcSight condition logic
plus a field-mapping cheat sheet (e.g. ArcSight often duplicates the same
value across `attackerServiceName`/`deviceCustomString1/2/4`/
`targetServiceName` — the model is told to collapse these into one
`ProcessCommandLine has_any(...)` check rather than repeating it per
source field) and returns both a KQL and an SPL query as fenced code blocks.

### Coverage validation — `backend/translation_validator.py`
Since "does it compile" says nothing about whether detection logic was
preserved, this extracts every required match-term and exclusion-term
directly from the ArcSight condition text (same deterministic approach as
MITRE extraction) and checks the generated KQL/SPL for:
- Every required term actually present (`missing_required` if not)
- Every exclusion term present **and in a negated context**
  (`wrongly_included_as_match` catches the dangerous case where an
  exclusion term appears but isn't actually negated — meaning it'd fire
  as a false positive rather than being filtered out)

Returns a `coverage_pct` and `passed` boolean. **Important gotcha already
hit once:** `passed` is a `@property`, not a stored dataclass field —
always serialize via `.to_dict()`, never raw `.__dict__`, or `passed`
silently disappears from JSON responses (this caused a real bug).

### Runbook generation — `backend/threat_analysis_prompts.py`
Generates the LLM-appropriate parts of a detection-engineering runbook:
threat analysis + MITRE technique table, detection review (false-positive
sources, false-negative/evasion gaps, time-window sanity, missing triage
fields), a Tier-1 analyst triage guide, and rule naming suggestions.
Returns structured JSON.

**Deliberately excluded:** whether Microsoft Defender already has native
coverage for this technique. A local LLM has no reliable, current
knowledge of Microsoft's product behavior — this is captured as a
required **human-entered** field (`MDECoverageAssessment`: verdict +
notes) in `/api/save-runbook`, never LLM-generated. Don't let a future
"improvement" quietly turn this into an LLM field — that's a deliberate
safety boundary, not an oversight.

### Live validation — `backend/splunk_client.py`
`SplunkTestClient` is a **read-only** client that runs the translated SPL
as a bounded `oneshot` search against a real Splunk instance (via its
REST API, port 8089 by default) and returns real hit counts, sample
events, and Splunk's own real error messages — strictly better ground
truth than the heuristic validator for actual syntax/runtime correctness.
Never creates, schedules, or modifies anything in Splunk.

### API surface (`app.py`)
- `POST /api/translate` — legacy Sigma-path single-rule translate + pySigma compile
- `GET /api/trace/{rule_name}` — full per-stage pipeline trace for debugging
- `POST /api/test-firing` — synthetic true/false-positive event test (Sigma path)
- `POST /api/translate-direct` — **primary endpoint**: raw ArcSight rule in,
  metadata + KQL + SPL + coverage validation + git-ready output text out
- `POST /api/validate` — standalone coverage check against an existing/hand-written query
- `POST /api/generate-runbook` — LLM runbook sections
- `POST /api/save-runbook` — merges runbook + human MDE verdict, writes final
  `.txt` to `git_ready_output/`
- `POST /api/test-live-splunk` — live Splunk search test

## 3. Where we've reached so far

- Both pipelines (Sigma-path and direct-path) are functional.
- Several real bugs have been found and fixed along the way (documented
  inline in the relevant files' comments/docstrings): a condition-string
  parsing bug that made every exclusion-bearing Sigma rule fail
  test-firing regardless of correctness; a root-level `condition` key the
  LLM sometimes hallucinates into Sigma YAML; correlation rules needing
  a specific 3-document YAML structure; a port collision between the
  FastAPI backend and a local Splunk test instance (both defaulted to
  port 8000 — backend moved to 8001); the `passed`-property serialization
  bug above.
- The whole stack was just containerized (`Dockerfile.backend`,
  `Dockerfile.frontend`, `docker-compose.yml`) — LM Studio stays on the
  host (GUI app, not containerized), reached via `host.docker.internal`.
- **Currently mid-debugging:** live Splunk validation end-to-end test using
  a real ADfind detection rule as the test case — most recently, tracking
  down why seeded test events weren't matching (a field-name/EventCode
  mismatch between the seeding script and the actual generated SPL's
  filter conditions). This may or may not be fully resolved by the time
  you read this — check with the person before assuming it's done.
- The current frontend (`frontend.py`) is a single-file Streamlit app with
  3 tabs (Sigma single-rule, Sigma batch, direct-path) that grew
  incrementally alongside the backend — it works, but wasn't designed
  holistically, which is why a rebuild is being considered now.

## 4. What we need from you: a new frontend

Design and build a new frontend that:

1. **Covers every backend endpoint listed in section 2** — don't drop any
   existing capability. Check `app.py` directly for the exact current
   request/response shapes rather than trusting this document for field
   names, since it may drift from the live code.
2. **Fits the actual shape of the data**, not a generic CRUD UI — e.g. the
   MITRE tactic's `mitre_source` field should be visually distinct
   depending on whether it was extracted vs. missing, since that
   trustworthiness distinction matters to the person reviewing it before
   committing a rule to their git repo. The MDE coverage verdict must
   stay a clearly human-input field, never rendered as if the LLM produced it.
3. **Adds an automatic background health check**: on load (and on a
   periodic interval, e.g. every 30-60s), check reachability of:
   - The FastAPI backend itself
   - LM Studio (the backend could expose a small `/api/health` proxy for
     this, or the frontend could hit LM Studio's `/v1/models` directly if
     network-reachable from wherever the frontend runs)
   - The configured Splunk instance, if one is set (via
     `SplunkTestClient.test_connection()` logic, which already exists
     server-side)
   Surface this as a simple, persistent status indicator (e.g. a small
   header bar with three colored dots/badges) so the person always knows
   what's actually reachable before they try to use a feature that needs it.
4. **Adds a track record / audit log**: every translation, validation run,
   runbook generation, and live Splunk test should be recorded (rule name,
   timestamp, outcome/pass-fail, which endpoint) and viewable as a
   history/log view in the UI — a simple persistent store (SQLite, a JSON
   lines file, whatever fits your stack) is fine; it doesn't need to be
   fancy, but it needs to survive a page refresh and ideally a container
   restart (mount it as a volume like `git_ready_output/` and `logs/`
   already are in `docker-compose.yml`).
5. **Preserves the git-ready output workflow** — the end goal of a lot of
   this tool is producing a `.txt` file suitable for committing to a
   detection-engineering runbook repo; don't lose that download/save path
   in a redesign.

## 5. Before you start writing code

Please summarize back:
- Your understanding of the two pipelines and why the direct path exists
- Which backend endpoints you found by actually reading `app.py`, and
  whether their real shapes match what's described above (flag any drift)
- Your proposed frontend architecture/framework choice and why
- Your plan for the health-check and audit-log features specifically

This is a genuine check for alignment, not a formality — this codebase
has already had several bugs caused by assumptions not matching the
actual running code, and the fastest way to add another one is to start
generating UI code before confirming you're working from accurate premises.
