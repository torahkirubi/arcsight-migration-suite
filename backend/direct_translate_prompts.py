"""
direct_translate_prompts.py - Direct Path Prompts & Helpers for ArcSight -> KQL & SPL

Supplies field mapping cheat-sheets, optimization instructions (collapsing redundant
ArcSight custom strings), and extracts fenced code blocks from LLM outputs.
"""

import re
from typing import Dict, Tuple

FIELD_MAPPING_CHEAT_SHEET = """
### ArcSight to Microsoft Defender (KQL) Field Mappings:
- attackerServiceName / deviceCustomString1 / deviceCustomString2 / deviceCustomString4 / targetServiceName -> ProcessCommandLine or FileName
- deviceHostName / destinationHostName -> DeviceName
- destinationUserName / sourceUserName -> AccountName or InitiatingProcessAccountName
- destinationAddress / sourceAddress -> RemoteIP or IPAddress
- destinationPort -> RemotePort
- deviceProcessName / sourceProcessName -> FileName or InitiatingProcessFileName
- parentProcessName / deviceCustomString3 -> InitiatingProcessParentFileName

Optimization Instruction:
In ArcSight rules, the same binary or search token is frequently duplicated across
attackerServiceName, deviceCustomString1, and deviceCustomString2.
Do NOT create redundant OR clauses per field. Collapse them into efficient KQL:
`ProcessCommandLine has_any ("token1", "token2")` or `FileName in~ ("token1", "token2")`

### ArcSight to Splunk (SPL) Field Mappings:
- attackerServiceName / deviceCustomString1 / deviceCustomString2 -> CommandLine or process
- deviceHostName / destinationHostName -> dest or host
- destinationUserName / sourceUserName -> user
- destinationAddress / sourceAddress -> dest_ip or src_ip
- destinationPort -> dest_port
- deviceProcessName -> process_name or Image

Optimization Instruction:
Collapse redundant checks into SPL terms or `CommandLine IN ("*token1*", "*token2*")` or `process_name IN ("bin1", "bin2")`.
- Wildcard Filtering: When matching fields against patterns with wildcards (*) using the IN operator, always use | search Field IN (...) rather than | where. Splunk treats asterisks as literal characters inside where clauses.
- Time Handling: Do not append runtime relative time calculations like | where _time >= relative_time(...) unless explicitly requested. Rely on base search parameters (e.g., earliest=-1m) or let the SIEM execution schedule handle windowing.

### Field Mapping & Exclusion Grouping Instruction:
Ensure multi-term exclusions are properly grouped and negated according to the target language's order of operations.
Optimization rules (such as `has_any` or `IN (...)`) apply ONLY to positive match conditions.
NEVER combine or invert exclusion filters into positive/inclusive matches.
"""

DIRECT_TRANSLATE_SYSTEM_PROMPT = f"""You are an elite Detection Engineer and SIEM Migration Specialist.
Your task is to translate legacy ArcSight ESM correlation rules into modern, production-grade Microsoft Defender XDR (KQL) and Splunk (SPL) queries.

{FIELD_MAPPING_CHEAT_SHEET}

### STRICT DIRECTIVES - LOGICAL OPERATOR FIDELITY:
1. You MUST preserve all negation and exclusion logic. If the ArcSight rule excludes a string, IP, or condition, the resulting KQL and SPL MUST use explicit negation (e.g., NOT, !=, not in()). Do not invert exclusion logic into inclusive matches.
2. Ensure multi-term exclusions are properly grouped and negated according to the target language's order of operations.
3. In KQL: Always use explicit negation operators for exclusions:
   - Single-term exclusion: `| where InitiatingProcessAccountName != "service_account"` or `| where RemotePort != 80`
   - Multi-term exclusion: `| where not(ProcessCommandLine has_any ("excl1", "excl2"))` or `| where AccountName !in~ ("excl1", "excl2")`
   - NEVER map ArcSight exclusion operators (NE, DoesNotContain, NOT) into positive `has_any` or `in` clauses.
4. In SPL: Always use explicit negation operators for exclusions:
   - Single-term exclusion: `NOT (user="service_account")` or `NOT (dest_port=80)` or `dest_port!=80`
   - Multi-term exclusion: `NOT (CommandLine IN ("*excl1*", "*excl2*"))` or `NOT (process_name IN ("excl1", "excl2"))`
   - Explicit grouping: Wrap negative conditions with parentheses to ensure boolean precedence is strictly maintained.

### STRICT DIRECTIVES - SPL SYNTAX CONSTRAINTS:
1. Wildcard Filtering: When matching fields against patterns with wildcards (*) using the IN operator, always use | search Field IN (...) rather than | where. Splunk treats asterisks as literal characters inside where clauses.
2. Time Handling: Do not append runtime relative time calculations like | where _time >= relative_time(...) unless explicitly requested. Rely on base search parameters (e.g., earliest=-1m) or let the SIEM execution schedule handle windowing.

STRICT OUTPUT RULES:
1. Return ONLY the queries inside fenced code blocks:
```kql
<Your KQL Query>
```

```spl
<Your SPL Query>
```
2. In KQL: Always begin with the appropriate schema table (typically `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, or `IdentityLogonEvents`). Include time filtering or aggregation if specified.
3. In SPL: Always start with the relevant index/sourcetype or macro (e.g. `index=main` or `index=wineventlog`) and pipe (|) commands cleanly.
   - When matching fields against patterns with wildcards (*) using the IN operator, always use | search Field IN (...) rather than | where. Splunk treats asterisks as literal characters inside where clauses.
   - Do not append runtime relative time calculations like | where _time >= relative_time(...) unless explicitly requested. Rely on base search parameters (e.g., earliest=-1m) or let the SIEM execution schedule handle windowing.
4. Ensure all required match terms are present.
5. Ensure all exclusion/filtering terms are explicitly NEGATED (`!=`, `!has`, `NOT (...)`) to avoid false positives.
6. Do NOT invent fields that do not exist in modern SIEM schemas.
"""


def build_direct_translate_prompt(
    rule_name: str,
    severity: str,
    raw_condition: str,
    frequency_str: str,
    group_by: list,
    mitre_tactic: str = None,
    required_terms: list = None,
    exclusion_terms: list = None,
    asim_mappings: dict = None,
) -> str:
    """Build the user prompt for the direct translation pipeline."""
    exclusion_section = ""
    if exclusion_terms:
        exclusion_section = f"""
### Identified Exclusion Filters (CRITICAL - MUST BE EXPLICITLY NEGATED):
{', '.join(exclusion_terms)}
"""

    asim_section = ""
    if asim_mappings:
        formatted_mappings = "\n".join(
            f"- {src} -> {dst}" for src, dst in asim_mappings.items()
        )
        asim_section = f"""
### ASIM Schema Field Mappings:
{formatted_mappings}
"""

    return f"""Translate the following ArcSight ESM Rule to both KQL and SPL.

### Rule Name:
{rule_name}

### Severity:
{severity}

### Frequency / Aggregation:
{frequency_str}
Group By: {', '.join(group_by) if group_by else 'None'}

### MITRE ATT&CK Tactic:
{mitre_tactic or 'Unknown / Not specified'}

### Raw ArcSight Condition Logic:
{raw_condition}
{exclusion_section}{asim_section}
### Strict Directives (Logical Operator Fidelity):
- You MUST preserve all negation and exclusion logic. If the ArcSight rule excludes a string, IP, or condition, the resulting KQL and SPL MUST use explicit negation (e.g., NOT, !=, not in()). Do not invert exclusion logic into inclusive matches.
- Ensure multi-term exclusions are properly grouped and negated according to the target language's order of operations.

### Strict Directives (SPL Syntax Constraints):
- Wildcard Filtering: When matching fields against patterns with wildcards (*) using the IN operator, always use | search Field IN (...) rather than | where. Splunk treats asterisks as literal characters inside where clauses.
- Time Handling: Do not append runtime relative time calculations like | where _time >= relative_time(...) unless explicitly requested. Rely on base search parameters (e.g., earliest=-1m) or let the SIEM execution schedule handle windowing.

Provide the optimized KQL and SPL queries formatted strictly within ```kql and ```spl code blocks.
"""


def sanitize_query(query: str) -> str:
    """
    Aggressively sanitizes generated queries by stripping Markdown code block
    fences (e.g. ```kql, ```spl, ```splunk, ```), trailing backticks, and any
    accidental markdown formatting. Preserves legitimate Splunk macro backticks.
    """
    if not query:
        return ""
    text = query.strip()

    # 1. Remove entire lines that are purely markdown fences (``` or ```lang)
    lines = text.splitlines()
    cleaned_lines = []
    for line in lines:
        stripped = line.strip()
        if re.match(r"^```[a-zA-Z0-9_-]*\s*$", stripped):
            continue
        cleaned_lines.append(line)
    text = "\n".join(cleaned_lines).strip()

    # 2. Strip leading ```lang or ``` if attached to the beginning of text
    text = re.sub(r"^```[a-zA-Z0-9_-]*\s*", "", text)
    # 3. Strip trailing ``` if attached to the end of text
    text = re.sub(r"\s*```$", "", text)
    # 4. Remove any remaining ```lang or ``` anywhere in the string
    text = re.sub(r"```[a-zA-Z0-9_-]*", "", text)
    text = text.replace("```", "").strip()

    # 5. If the LLM wrapped the entire query in a single pair of backticks (`...`),
    # strip the outer backticks if it's an entire query rather than a single Splunk macro.
    if text.startswith("`") and text.endswith("`") and len(text) > 2:
        inner = text[1:-1].strip()
        if any(c in inner for c in ["\n", "|", " "]):
            text = inner

    return text.strip()


def extract_queries_from_response(llm_output: str) -> Tuple[str, str]:
    """
    Extracts KQL and SPL code blocks from the LLM completion text.
    Aggressively sanitizes extracted queries to strip markdown code block syntax.
    """
    kql_query = ""
    spl_query = ""

    # Match ```kql ... ```
    kql_match = re.search(r'```(?:kql|csl)\s*\n?(.*?)(?:```|$)', llm_output, re.DOTALL | re.IGNORECASE)
    if kql_match:
        kql_query = kql_match.group(1).strip()

    # Match ```spl ... ```
    spl_match = re.search(r'```(?:spl|splunk)\s*\n?(.*?)(?:```|$)', llm_output, re.DOTALL | re.IGNORECASE)
    if spl_match:
        spl_query = spl_match.group(1).strip()

    # Fallback if fences didn't have specific language tags
    if not kql_query and not spl_query:
        all_blocks = [
            b.strip()
            for b in re.findall(r'```[a-zA-Z0-9_-]*\s*\n?(.*?)(?:```|$)', llm_output, re.DOTALL)
            if b.strip()
        ]
        if len(all_blocks) >= 2:
            kql_query = all_blocks[0]
            spl_query = all_blocks[1]
        elif len(all_blocks) == 1:
            block = all_blocks[0]
            if block.startswith("index=") or block.startswith("search ") or " | stats" in block:
                spl_query = block
            else:
                kql_query = block
    elif kql_query and not spl_query:
        all_blocks = [
            b.strip()
            for b in re.findall(r'```[a-zA-Z0-9_-]*\s*\n?(.*?)(?:```|$)', llm_output, re.DOTALL)
            if b.strip()
        ]
        remaining = [b for b in all_blocks if sanitize_query(b) != sanitize_query(kql_query)]
        if remaining:
            spl_query = remaining[0]
    elif spl_query and not kql_query:
        all_blocks = [
            b.strip()
            for b in re.findall(r'```[a-zA-Z0-9_-]*\s*\n?(.*?)(?:```|$)', llm_output, re.DOTALL)
            if b.strip()
        ]
        remaining = [b for b in all_blocks if sanitize_query(b) != sanitize_query(spl_query)]
        if remaining:
            kql_query = remaining[0]

    # Heuristic fallback if LLM output raw SPL without code fences
    if not spl_query and ("index=" in llm_output or "search " in llm_output or "| stats" in llm_output):
        cleaned = llm_output.strip()
        for line in cleaned.splitlines():
            ls = line.strip()
            if ls.startswith("index=") or ls.startswith("search ") or ls.startswith("|"):
                spl_query = cleaned[cleaned.find(ls):].strip()
                break

    return sanitize_query(kql_query), sanitize_query(spl_query)


