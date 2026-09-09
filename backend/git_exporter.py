"""
git_exporter.py - Git-Ready Output Formatter & Storage

Assembles the final production detection engineering runbook (.txt format)
merging:
1. Parsed ArcSight rule metadata
2. STRICTLY HUMAN-ENTERED Microsoft Defender (MDE) coverage verdict + notes
3. Validated KQL query with coverage metrics
4. Validated SPL query with coverage metrics
5. LLM-generated Threat Analysis & Triage Guide
6. Audit trail signature
"""

from datetime import datetime, timezone
import os
import re
from typing import Any, Dict, Optional


OUTPUT_DIR = os.environ.get(
    "GIT_READY_OUTPUT_DIR",
    os.path.join(os.path.dirname(__file__), "git_ready_output"),
)


def sanitize_filename(name: str) -> str:
    """Sanitize rule name for filesystem use."""
    clean = re.sub(r'[^a-zA-Z0-9_\-\.]+', '_', name).strip('_')
    return clean or "unnamed_rule"


def generate_git_ready_text(
    rule_name: str,
    severity: str,
    priority: int,
    mitre_tactic: Optional[str],
    mitre_source: str,
    mitre_uri: Optional[str],
    frequency_str: str,
    group_by: list,
    kql_query: str,
    kql_validation: Dict[str, Any],
    spl_query: str,
    spl_validation: Dict[str, Any],
    threat_analysis: Dict[str, Any],
    mde_verdict: str,
    mde_notes: str,
    reviewer_name: str = "Detection Engineer",
    llm_model: str = "qwen2.5-coder",
) -> str:
    """
    Constructs the formatted text runbook ready for commit to a Git detection repo.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Format techniques
    techs = threat_analysis.get("mitre_techniques", [])
    tech_lines = []
    if isinstance(techs, list) and techs:
        for t in techs:
            if isinstance(t, dict):
                tech_lines.append(f"- {t.get('technique_id', 'N/A')}: {t.get('technique_name', '')} ({t.get('tactic', '')})")
            else:
                tech_lines.append(f"- {str(t)}")
    else:
        tech_lines.append(f"- Tactic: {mitre_tactic or 'None specified'}")

    techs_str = "\n".join(tech_lines)

    # Format detection review
    review = threat_analysis.get("detection_review", {})
    fps = review.get("false_positive_sources", [])
    fps_str = "\n".join(f"- {fp}" for fp in fps) if fps else "- Standard admin activity review required."

    evasions = review.get("evasion_blindspots", [])
    evasions_str = "\n".join(f"- {ev}" for ev in evasions) if evasions else "- Binary renaming or command-line obfuscation."

    triage = threat_analysis.get("analyst_triage_guide", {})
    questions = triage.get("initial_questions", [])
    questions_str = "\n".join(f"- {q}" for q in questions) if questions else "- Verify executing user and host role."

    containment = triage.get("containment_steps", [])
    containment_str = "\n".join(f"- {c}" for c in containment) if containment else "- Isolate endpoint if unauthorized execution."

    escalation = triage.get("escalation_criteria", [])
    escalation_str = "\n".join(f"- {e}" for e in escalation) if escalation else "- Host is critical infrastructure or Domain Controller."

    # Format validation
    kql_passed = "PASSED" if kql_validation.get("passed") else "FAILED/WARNING"
    kql_cov = kql_validation.get("coverage_pct", 0)
    spl_passed = "PASSED" if spl_validation.get("passed") else "FAILED/WARNING"
    spl_cov = spl_validation.get("coverage_pct", 0)

    content = f"""================================================================================
DETECTION ENGINEERING SPECIFICATION & RUNBOOK
RULE NAME: {rule_name}
SEVERITY: {severity} (ArcSight Priority: {priority})
MITRE ATT&CK TACTIC: {mitre_tactic or 'None'} (Trustworthiness: {mitre_source})
SOURCE RESOURCE URI: {mitre_uri or 'N/A'}
FREQUENCY / THRESHOLD: {frequency_str}
AGGREGATION / GROUP BY: {', '.join(group_by) if group_by else 'None'}
GENERATED TIMESTAMP: {now}
================================================================================

--------------------------------------------------------------------------------
1. MICROSOFT DEFENDER (MDE) NATIVE COVERAGE ASSESSMENT [HUMAN REVIEW ONLY]
--------------------------------------------------------------------------------
VERDICT: {mde_verdict or 'HUMAN VERDICT PENDING'}
REVIEWED BY: {reviewer_name}
ANALYST JUSTIFICATION / PRODUCT NOTES:
{mde_notes.strip() if mde_notes else 'No analyst notes provided.'}

--------------------------------------------------------------------------------
2. TRANSLATED MICROSOFT DEFENDER XDR QUERY (KQL)
--------------------------------------------------------------------------------
{kql_query.strip()}

[KQL Coverage Validation: {kql_passed} | Score: {kql_cov}%]
- Missing Required Terms: {', '.join(kql_validation.get('missing_required', [])) or 'None (All Present)'}
- Wrongly Included Exclusions: {', '.join(kql_validation.get('wrongly_included_as_match', [])) or 'None'}

--------------------------------------------------------------------------------
3. TRANSLATED SPLUNK QUERY (SPL)
--------------------------------------------------------------------------------
{spl_query.strip()}

[SPL Coverage Validation: {spl_passed} | Score: {spl_cov}%]
- Missing Required Terms: {', '.join(spl_validation.get('missing_required', [])) or 'None (All Present)'}
- Wrongly Included Exclusions: {', '.join(spl_validation.get('wrongly_included_as_match', [])) or 'None'}

--------------------------------------------------------------------------------
4. THREAT ANALYSIS & ATT&CK TECHNIQUE MAPPING
--------------------------------------------------------------------------------
THREAT SUMMARY:
{threat_analysis.get('threat_summary', 'No summary generated.')}

MITRE ATT&CK TECHNIQUES:
{techs_str}

--------------------------------------------------------------------------------
5. DETECTION REVIEW & RESILIENCE EVALUATION
--------------------------------------------------------------------------------
POTENTIAL FALSE POSITIVES:
{fps_str}

EVASION BLINDSPOTS:
{evasions_str}

AGGREGATION / TIME-WINDOW SANITY:
{review.get('time_window_evaluation', 'Threshold appears consistent with observed activity.')}

MISSING RECOMMENDED TRIAGE FIELDS:
{', '.join(review.get('missing_triage_fields', [])) or 'None identified'}

--------------------------------------------------------------------------------
6. TIER-1 ANALYST TRIAGE & CONTAINMENT GUIDE
--------------------------------------------------------------------------------
INITIAL INVESTIGATION QUESTIONS:
{questions_str}

CONTAINMENT & REMEDIATION ACTIONS:
{containment_str}

ESCALATION CRITERIA:
{escalation_str}

--------------------------------------------------------------------------------
7. AUDIT & PROVENANCE TRAIL
--------------------------------------------------------------------------------
MIGRATION ENGINE: ArcSight Migration Suite (Direct Path)
LLM CLIENT: {llm_model}
MITRE PROVENANCE: {mitre_source}
PARSER INTEGRITY: Deterministic Keyword Boundary Parsing (Zero LLM)
MDE HUMAN SAFETY PROTOCOL: Strictly Enforced
================================================================================
"""
    return content


def save_git_ready_runbook(
    rule_name: str,
    file_content: str,
    output_dir: str = OUTPUT_DIR,
) -> Dict[str, Any]:
    """
    Saves the git-ready runbook to a .txt file on disk.
    """
    os.makedirs(output_dir, exist_ok=True)
    filename = f"{sanitize_filename(rule_name)}.txt"
    file_path = os.path.join(output_dir, filename)

    with open(file_path, "w", encoding="utf-8") as f:
        f.write(file_content)

    return {
        "filename": filename,
        "file_path": file_path,
        "bytes_written": len(file_content.encode("utf-8")),
    }

