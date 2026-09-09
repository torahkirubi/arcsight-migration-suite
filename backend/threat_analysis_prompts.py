"""
threat_analysis_prompts.py - Detection Runbook & Threat Analysis Prompting

Generates detection engineering documentation:
- Threat Analysis & MITRE technique mappings
- Detection Review (False positive risks, evasion blind spots, missing triage fields)
- Tier-1 Analyst Triage Guide (investigation steps, remediation/containment steps)
- Rule Naming Suggestions

STRICT SAFETY BOUNDARY:
The LLM is explicitly forbidden from generating Microsoft Defender (MDE) coverage assessments.
MDE coverage is strictly a human-entered assessment.
"""

import json
import re
from typing import Any, Dict

THREAT_ANALYSIS_SYSTEM_PROMPT = """You are a Principal Detection Engineer and SOC Operations Lead.
Analyze the provided SIEM correlation rule and generate a comprehensive detection runbook.

STRICT OPERATIONAL SAFETY DIRECTIVE:
DO NOT attempt to assess whether Microsoft Defender for Endpoint (MDE) or Microsoft Sentinel
already has native out-of-the-box coverage for this technique. You do not possess real-time
telemetry or product change-logs. MDE coverage assessment is strictly a HUMAN-IN-THE-LOOP responsibility.

You must respond ONLY with a valid JSON object with the following schema:
{
  "threat_summary": "High-level summary of the adversary behavior and risk",
  "mitre_techniques": [
    {
      "technique_id": "e.g. T1087.002",
      "technique_name": "e.g. Domain Account Discovery",
      "tactic": "e.g. Discovery"
    }
  ],
  "detection_review": {
    "false_positive_sources": ["Legitimate administrative scripts", "Scheduled discovery tools"],
    "evasion_blindspots": ["Adversary renaming binary", "Encoding command line"],
    "time_window_evaluation": "Sanity check on the rule's event aggregation threshold",
    "missing_triage_fields": ["ParentProcessCommandLine", "LoggedOnUsers"]
  },
  "analyst_triage_guide": {
    "triage_priority": "High/Medium/Low",
    "initial_questions": ["What user account executed the command?", "Is the host an administrative jump box?"],
    "containment_steps": ["Isolate host via EDR if unauthorized", "Reset compromised credentials"],
    "escalation_criteria": ["Execution from domain controller or key executive workstation"]
  },
  "rule_naming_suggestions": [
    "ADFind Active Directory Reconnaissance Detected",
    "Suspicious Domain Object Enumeration via ADFind"
  ]
}
"""


def build_threat_analysis_prompt(
    rule_name: str,
    severity: str,
    mitre_tactic: str,
    raw_condition: str,
    kql_query: str,
    spl_query: str,
) -> str:
    """Build the threat analysis prompt for the LLM."""
    return f"""Analyze this detection rule and output the structured JSON runbook:

Rule Name: {rule_name}
Severity: {severity}
Extracted MITRE Tactic: {mitre_tactic or 'Unknown'}
Raw ArcSight Condition:
{raw_condition}

Translated KQL:
{kql_query}

Translated SPL:
{spl_query}
"""


def parse_threat_analysis_response(raw_output: str) -> Dict[str, Any]:
    """
    Parses JSON from the LLM output, stripping markdown fences if present.
    Provides robust fallbacks if JSON is slightly malformed.
    """
    clean_text = raw_output.strip()

    # Strip ```json ... ``` markdown fences
    m = re.search(r'```(?:json)?\s*\n(.*?)\n```', clean_text, re.DOTALL | re.IGNORECASE)
    if m:
        clean_text = m.group(1).strip()
    else:
        # Or look for { ... }
        m_brace = re.search(r'(\{.*\})', clean_text, re.DOTALL)
        if m_brace:
            clean_text = m_brace.group(1).strip()

    try:
        data = json.loads(clean_text)
        # Guarantee no MDE coverage key was hallucinated into output
        data.pop("mde_coverage", None)
        data.pop("mde_coverage_assessment", None)
        return data
    except Exception:
        # Fallback structured dict
        return {
            "threat_summary": raw_output[:300] + "...",
            "mitre_techniques": [],
            "detection_review": {
                "false_positive_sources": ["Review internal administrative utilities"],
                "evasion_blindspots": ["Binary renaming and CLI obfuscation"],
                "time_window_evaluation": "Standard threshold evaluation",
                "missing_triage_fields": [],
            },
            "analyst_triage_guide": {
                "triage_priority": "Medium",
                "initial_questions": ["Inspect initiating process and account privilege"],
                "containment_steps": ["Verify activity with user/asset owner"],
                "escalation_criteria": ["Multiple systems alerted simultaneously"],
            },
            "rule_naming_suggestions": [rule_name],
            "raw_output": raw_output,
        }

