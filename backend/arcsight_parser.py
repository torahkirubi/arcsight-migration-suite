"""
arcsight_parser.py - Deterministic Regex Parser for ArcSight ESM Rules.

Zero LLM involvement.
Robustly parses ArcSight rule exports (HTML/XML/text condition blocks) and extracts:
- Rule Name
- Priority-to-Severity mapping (0-10 -> Low/Medium/High/Critical)
- Frequency (event count and time window)
- Group-by / Aggregation fields
- MITRE ATT&CK tactic (pulled directly from eventAnnotationStage URI)
- Required match terms and negated exclusion terms for coverage validation
- Raw boolean condition logic

CRITICAL PITFALL AVOIDED:
ArcSight exports frequently drop closing parentheses per clause.
This parser does NOT use paren-balancing; it uses boolean keyword boundaries
(And / Or) and atomic clause matching to avoid cascading syntax errors.
"""

from dataclasses import dataclass, field
import re
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class FrequencyInfo:
    event_count: int = 1
    time_window_value: int = 0
    time_window_unit: str = "Minutes"
    raw_frequency: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_count": self.event_count,
            "time_window_value": self.time_window_value,
            "time_window_unit": self.time_window_unit,
            "raw_frequency": self.raw_frequency,
        }


@dataclass
class ConditionClause:
    field_name: str
    operator: str
    value: str
    is_negated: bool = False
    raw_clause: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "field_name": self.field_name,
            "operator": self.operator,
            "value": self.value,
            "is_negated": self.is_negated,
            "raw_clause": self.raw_clause,
        }


@dataclass
class ParsedArcSightRule:
    rule_name: str
    priority: int
    severity: str
    frequency: FrequencyInfo
    group_by_fields: List[str]
    mitre_tactic: Optional[str]
    mitre_source: str  # "extracted from rule" | "missing"
    mitre_uri: Optional[str]
    raw_condition: str
    clauses: List[ConditionClause] = field(default_factory=list)
    required_terms: List[str] = field(default_factory=list)
    exclusion_terms: List[str] = field(default_factory=list)
    referenced_fields: List[str] = field(default_factory=list)
    active_lists: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_name": self.rule_name,
            "priority": self.priority,
            "severity": self.severity,
            "frequency": self.frequency.to_dict(),
            "group_by_fields": self.group_by_fields,
            "mitre_tactic": self.mitre_tactic,
            "mitre_source": self.mitre_source,
            "mitre_uri": self.mitre_uri,
            "raw_condition": self.raw_condition,
            "clauses": [c.to_dict() for c in self.clauses],
            "required_terms": self.required_terms,
            "exclusion_terms": self.exclusion_terms,
            "referenced_fields": self.referenced_fields,
            "active_lists": self.active_lists,
        }


ParsedRule = ParsedArcSightRule


def map_priority_to_severity(priority: int) -> str:
    """
    Deterministic ArcSight priority (0-10) to modern SIEM severity mapping.
    0-3: Low
    4-6: Medium
    7-8: High
    9-10: Critical
    """
    if priority <= 3:
        return "Low"
    elif priority <= 6:
        return "Medium"
    elif priority <= 8:
        return "High"
    else:
        return "Critical"


def extract_rule_name(raw_text: str) -> str:
    """Extract rule name from SetEventField(name, ...), XML <Name>, or key-value."""
    # Pattern 1: SetEventField(name, "...") or SetEventField(name, '...')
    m = re.search(r'SetEventField\s*\(\s*name\s*,\s*["\']([^"\']+)["\']', raw_text, re.IGNORECASE)
    if m:
        return m.group(1).strip()

    # Pattern 2: XML tag <Name>...</Name>
    m = re.search(r'<Name>\s*([^<\r\n]+)\s*</Name>', raw_text, re.IGNORECASE)
    if m:
        return m.group(1).strip()

    # Pattern 3: Key-value e.g. Rule Name: ...
    m = re.search(r'(?:Rule\s*Name|RuleName)\s*[:=]\s*([^\r\n]+)', raw_text, re.IGNORECASE)
    if m:
        return m.group(1).strip().strip('"\'')

    # Pattern 4: name="Rule Name"
    m = re.search(r'\bname\s*=\s*["\']([^"\']+)["\']', raw_text, re.IGNORECASE)
    if m:
        return m.group(1).strip()

    return "Untitled ArcSight Rule"


def extract_priority(raw_text: str) -> Tuple[int, str]:
    """Extract priority integer (0-10) and compute severity."""
    # Pattern 1: SetEventField(basePriority, 7) or SetEventField(priority, 7)
    m = re.search(r'SetEventField\s*\(\s*(?:basePriority|priority)\s*,\s*(\d+)', raw_text, re.IGNORECASE)
    if m:
        p = int(m.group(1))
        return min(max(p, 0), 10), map_priority_to_severity(p)

    # Pattern 2: XML <Priority>7</Priority> or <basePriority>7</basePriority>
    m = re.search(r'<(?:basePriority|Priority)>\s*(\d+)\s*</', raw_text, re.IGNORECASE)
    if m:
        p = int(m.group(1))
        return min(max(p, 0), 10), map_priority_to_severity(p)

    # Pattern 3: Priority: 7
    m = re.search(r'\bPriority\s*[:=]\s*(\d+)', raw_text, re.IGNORECASE)
    if m:
        p = int(m.group(1))
        return min(max(p, 0), 10), map_priority_to_severity(p)

    # Pattern 4: Direct severity text (e.g. Severity: High)
    m = re.search(r'\bSeverity\s*[:=]\s*(Low|Medium|High|Critical)\b', raw_text, re.IGNORECASE)
    if m:
        sev = m.group(1).capitalize()
        sev_to_p = {"Low": 2, "Medium": 5, "High": 8, "Critical": 10}
        return sev_to_p.get(sev, 5), sev

    return 5, "Medium"


def extract_frequency(raw_text: str) -> FrequencyInfo:
    """Extract event count and aggregation time window."""
    # Pattern 1: Matching N events in M Minutes/Seconds/Hours
    m = re.search(
        r'Matching\s+(\d+)\s+events?\s+in\s+(\d+)\s+(Minutes?|Seconds?|Hours?|min|sec|hrs?|m|s|h)\b',
        raw_text,
        re.IGNORECASE,
    )
    if m:
        count = int(m.group(1))
        win_val = int(m.group(2))
        unit = m.group(3).capitalize()
        if unit.startswith("Min") or unit == "M":
            unit = "Minutes"
        elif unit.startswith("Sec") or unit == "S":
            unit = "Seconds"
        elif unit.startswith("H"):
            unit = "Hours"
        return FrequencyInfo(
            event_count=count,
            time_window_value=win_val,
            time_window_unit=unit,
            raw_frequency=m.group(0),
        )

    # Pattern 2: TimeWindow: 5 min, Threshold: 3
    m_count = re.search(r'(?:Threshold|EventCount|Event\s*Count)\s*[:=]\s*(\d+)', raw_text, re.IGNORECASE)
    m_win = re.search(r'(?:TimeWindow|Time\s*Window|Window)\s*[:=]\s*(\d+)\s*(Minutes?|Seconds?|Hours?|min|sec|h)?', raw_text, re.IGNORECASE)
    if m_count or m_win:
        count = int(m_count.group(1)) if m_count else 1
        win_val = int(m_win.group(1)) if m_win else 0
        raw_unit = m_win.group(2) if (m_win and m_win.group(2)) else "Minutes"
        unit = "Minutes"
        if raw_unit.lower().startswith("sec"):
            unit = "Seconds"
        elif raw_unit.lower().startswith("h"):
            unit = "Hours"
        return FrequencyInfo(
            event_count=count,
            time_window_value=win_val,
            time_window_unit=unit,
            raw_frequency=f"{count} events in {win_val} {unit}",
        )

    return FrequencyInfo(event_count=1, time_window_value=0, time_window_unit="Minutes", raw_frequency="Single event match (Realtime)")


def extract_group_by(raw_text: str) -> List[str]:
    """Extract aggregated group-by fields."""
    patterns = [
        r'(?:groupByFields|groupByField|groupBy)\s*[:=]\s*([^\r\n<]+)',
        r'(?:AggregateBy|Aggregated\s*By|Group\s*By)\s*[:=]\s*([^\r\n<]+)',
        r'<groupByFields>\s*([^<]+)\s*</groupByFields>',
    ]
    for pat in patterns:
        m = re.search(pat, raw_text, re.IGNORECASE)
        if m:
            raw_fields = m.group(1).strip()
            fields = [re.sub(r'["\']', '', f).strip() for f in re.split(r'[,;|\s]+', raw_fields) if f.strip()]
            return [f for f in fields if f]

    # Look for GroupBy(...) in actions or conditions
    m = re.search(r'GroupBy\s*\(\s*([^)]+)\s*\)', raw_text, re.IGNORECASE)
    if m:
        fields = [f.strip().strip('"\'') for f in m.group(1).split(",") if f.strip()]
        return fields

    return []


def extract_mitre_tactic(raw_text: str) -> Tuple[Optional[str], str, Optional[str]]:
    """
    Extract MITRE ATT&CK tactic from ArcSight eventAnnotationStage Resource URI.
    Returns: (tactic_name, mitre_source, raw_uri)
    mitre_source is either "extracted from rule" or "missing".
    """
    # Pattern 1: SetEventField(eventAnnotationStage, <Resource URI="/All Stages/MITRE Tactics/Discovery".../>)
    m = re.search(
        r'SetEventField\s*\(\s*eventAnnotationStage\s*,\s*<Resource[^>]*URI="([^"]*MITRE\s*Tactics/([^"/]+)[^"]*)"',
        raw_text,
        re.IGNORECASE,
    )
    if m:
        uri = m.group(1)
        tactic = m.group(2).strip()
        return tactic, "extracted from rule", uri

    # Pattern 2: Direct Resource URI attribute
    m = re.search(r'URI="([^"]*/MITRE\s*Tactics/([^"/]+)[^"]*)"', raw_text, re.IGNORECASE)
    if m:
        uri = m.group(1)
        tactic = m.group(2).strip()
        return tactic, "extracted from rule", uri

    # Pattern 3: <eventAnnotationStage>...MITRE Tactics/Discovery...</eventAnnotationStage>
    m = re.search(r'MITRE\s*Tactics/([^"/<>\r\n]+)', raw_text, re.IGNORECASE)
    if m:
        tactic = m.group(1).strip()
        return tactic, "extracted from rule", f"/All Stages/MITRE Tactics/{tactic}"

    return None, "missing", None


def extract_raw_condition(raw_text: str) -> str:
    """Extract condition block text from ArcSight rule export."""
    # Pattern 1: <Conditions>...</Conditions> or <Condition>...</Condition>
    m = re.search(r'<Conditions?>\s*(.*?)\s*</Conditions?>', raw_text, re.DOTALL | re.IGNORECASE)
    if m:
        return m.group(1).strip()

    # Pattern 2: Condition: ... (up to Actions: or Aggregation: or double newline)
    m = re.search(
        r'(?:Condition|Conditions)\s*[:=]\s*(.*?)(?=\n\s*(?:Actions?|Aggregation|Group\s*By|Threshold|Rule|SetEventField)|$)',
        raw_text,
        re.DOTALL | re.IGNORECASE,
    )
    if m:
        return m.group(1).strip()

    # Pattern 3: Find outermost parenthesis block that contains common ArcSight operators
    m = re.search(r'(\([^\(\)]*(?:EQ|Contains|NE|doesNotContain)[^\(\)]*.*)', raw_text, re.DOTALL | re.IGNORECASE)
    if m:
        return m.group(1).strip()

    return raw_text.strip()


def parse_condition_clauses(condition_text: str) -> Tuple[List[ConditionClause], List[str], List[str], List[str]]:
    """
    Deterministically extracts condition clauses, required match terms,
    exclusion terms, and referenced fields.

    BYPASSING DROPPED PARENTHESES:
    ArcSight rule exports often drop a closing parenthesis per clause.
    We NEVER rely on global paren balancing.
    Instead, we:
    1. Segment clauses using boolean keyword boundaries ('And', 'Or', 'AND', 'OR').
    2. Within each segment, extract atomic predicates (Field Op Value or Op(Field, Value)).
    3. Determine negation via 'NE', 'doesNotContain', '!EQ', '!=', or leading 'NOT'.
    4. Collect positive match terms and negated exclusion terms.
    """
    clauses: List[ConditionClause] = []
    required_terms: List[str] = []
    exclusion_terms: List[str] = []
    referenced_fields: List[str] = []

    # Clean XML/HTML entities if present
    text = (
        condition_text
        .replace("&quot;", '"')
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
    )

    # Split by boolean operator boundaries: And / Or / AND / OR (accounting for optional parens)
    segments = re.split(
        r'(?:\s+(?:And|Or|AND|OR)\s+|\s+(?:And|Or|AND|OR)(?=\()|(?<=\))\s*(?:And|Or|AND|OR)\s+)',
        text,
        flags=re.IGNORECASE,
    )

    NEGATION_OPERATORS = {
        "NE", "!=", "<>", "!EQ", "!CONTAINS", "DOESNOTCONTAIN",
        "!HAS", "!IN", "!STARTSWITH", "!ENDSWITH", "!MATCHES"
    }

    # Pattern 1: Prefix Operator: !Contains(Field, "Value") or Contains(Field, "Value")
    prefix_pattern = re.compile(
        r'(!Contains|doesNotContain|!EQ|!has|!in|!StartsWith|!EndsWith|!matches|NE|!=|<>|EQ|Contains|IN|has|StartsWith|EndsWith|matches)\s*\(\s*([a-zA-Z0-9_\.]+)\s*,\s*["\']?([^"\'\(\)\r\n]+)["\']?\s*\)',
        re.IGNORECASE,
    )

    # Pattern 2: Infix Operator: Field !Contains "Value" or Field Contains "Value" or Field NE "Value"
    infix_pattern = re.compile(
        r'([a-zA-Z0-9_\.]+)\s*(!Contains|doesNotContain|!EQ|!has|!in|!StartsWith|!EndsWith|!matches|NE|!=|<>|EQ|Contains|IN|has|StartsWith|EndsWith|matches|==|=)\s+["\']?([^"\'\(\)\r\n]+)["\']?',
        re.IGNORECASE,
    )

    for raw_seg in segments:
        seg = raw_seg.strip()
        if not seg:
            continue

        # Check if the predicate itself is directly wrapped by a leading NOT or !
        is_wrapped_not = bool(re.match(r'^\(?\s*(?:NOT\b|!)\s*\(?', seg, re.IGNORECASE))

        matched = False

        # Try Prefix: Op(Field, Value)
        m_pref = prefix_pattern.search(seg)
        if m_pref:
            op = m_pref.group(1).strip()
            field_name = m_pref.group(2).strip()
            val = m_pref.group(3).strip().strip('"\'')
            is_neg = (op.upper() in NEGATION_OPERATORS) or is_wrapped_not

            clause = ConditionClause(
                field_name=field_name,
                operator=op,
                value=val,
                is_negated=is_neg,
                raw_clause=seg,
            )
            clauses.append(clause)
            matched = True

        # Try Infix: Field Op Value
        if not matched:
            m_inf = infix_pattern.search(seg)
            if m_inf:
                field_name = m_inf.group(1).strip()
                op = m_inf.group(2).strip()
                val = m_inf.group(3).strip().strip('"\'')
                is_neg = (op.upper() in NEGATION_OPERATORS) or is_wrapped_not

                clause = ConditionClause(
                    field_name=field_name,
                    operator=op,
                    value=val,
                    is_negated=is_neg,
                    raw_clause=seg,
                )
                clauses.append(clause)
                matched = True

        # Fallback: String literal in quotes inside the segment
        # Stricter: only mark as exclusion if string immediately follows a negation operator
        if not matched:
            quoted = re.findall(r'["\']([^"\']+)["\']', seg)
            for val in quoted:
                val = val.strip()
                if len(val) >= 2:
                    is_neg = bool(re.search(
                        r'(?:!Contains|doesNotContain|!EQ|NE|!=|<>|!has|!in|\bNOT\b|!)\s*\(?[^"\'\r\n]*?["\']' + re.escape(val) + r'["\']',
                        seg,
                        re.IGNORECASE,
                    ))
                    clause = ConditionClause(
                        field_name="unknown",
                        operator="doesNotContain" if is_neg else "Contains",
                        value=val,
                        is_negated=is_neg,
                        raw_clause=seg,
                    )
                    clauses.append(clause)

    # De-duplicate terms while maintaining ordering
    seen_req = set()
    seen_excl = set()
    seen_fields = set()

    for c in clauses:
        if c.field_name and c.field_name != "unknown" and c.field_name not in seen_fields:
            referenced_fields.append(c.field_name)
            seen_fields.add(c.field_name)

        clean_val = c.value.strip()
        if not clean_val or len(clean_val) < 2:
            continue

        if c.is_negated:
            if clean_val not in seen_excl:
                exclusion_terms.append(clean_val)
                seen_excl.add(clean_val)
        else:
            if clean_val not in seen_req:
                required_terms.append(clean_val)
                seen_req.add(clean_val)

    return clauses, required_terms, exclusion_terms, referenced_fields


def extract_active_lists(condition_text: str) -> List[Dict[str, str]]:
    """
    Extracts ArcSight ActiveList lookups from condition logic.
    Identifies InActiveList operations and extracts:
    - field: evaluated event field (e.g. destinationAddress, sourceUserName)
    - name: targeted ActiveList name (e.g. Malicious IPs, Terminated Users)
    Handles variations in whitespace and quote types (single or double).
    """
    active_lists: List[Dict[str, str]] = []
    if not condition_text:
        return active_lists

    # Pattern 1: Standard function call InActiveList(field, "list_name") or InActiveList(field, 'list_name')
    pattern_standard = re.compile(
        r'InActiveList\s*\(\s*([a-zA-Z0-9_.-]+)\s*,\s*["\']([^"\']+)["\']\s*\)',
        re.IGNORECASE,
    )
    for m in pattern_standard.finditer(condition_text):
        field_name = m.group(1).strip()
        list_name = m.group(2).strip()
        lookup = {"field": field_name, "name": list_name}
        if lookup not in active_lists:
            active_lists.append(lookup)

    # Pattern 2: Inverted arguments InActiveList("list_name", field)
    pattern_inverted = re.compile(
        r'InActiveList\s*\(\s*["\']([^"\']+)["\']\s*,\s*([a-zA-Z0-9_.-]+)\s*\)',
        re.IGNORECASE,
    )
    for m in pattern_inverted.finditer(condition_text):
        list_name = m.group(1).strip()
        field_name = m.group(2).strip()
        lookup = {"field": field_name, "name": list_name}
        if lookup not in active_lists:
            active_lists.append(lookup)

    # Pattern 3: Infix syntax: field InActiveList "list_name"
    pattern_infix = re.compile(
        r'\b([a-zA-Z0-9_.-]+)\s+InActiveList\s+["\']([^"\']+)["\']',
        re.IGNORECASE,
    )
    for m in pattern_infix.finditer(condition_text):
        field_name = m.group(1).strip()
        list_name = m.group(2).strip()
        lookup = {"field": field_name, "name": list_name}
        if lookup not in active_lists:
            active_lists.append(lookup)

    return active_lists


def parse_arcsight_rule(raw_text: str) -> ParsedArcSightRule:
    """
    Main entry point for deterministic extraction of ArcSight ESM rules.
    Takes raw ArcSight rule export text and returns a structured ParsedArcSightRule object.
    Zero LLM involvement.
    """
    rule_name = extract_rule_name(raw_text)
    priority, severity = extract_priority(raw_text)
    frequency = extract_frequency(raw_text)
    group_by_fields = extract_group_by(raw_text)
    mitre_tactic, mitre_source, mitre_uri = extract_mitre_tactic(raw_text)
    raw_condition = extract_raw_condition(raw_text)

    clauses, req_terms, excl_terms, ref_fields = parse_condition_clauses(raw_condition)
    active_lists = extract_active_lists(raw_condition) or extract_active_lists(raw_text)

    # Ensure fields evaluated by ActiveLists are registered in referenced_fields
    for al in active_lists:
        al_field = al.get("field")
        if al_field and al_field not in ref_fields:
            ref_fields.append(al_field)

    return ParsedArcSightRule(
        rule_name=rule_name,
        priority=priority,
        severity=severity,
        frequency=frequency,
        group_by_fields=group_by_fields,
        mitre_tactic=mitre_tactic,
        mitre_source=mitre_source,
        mitre_uri=mitre_uri,
        raw_condition=raw_condition,
        clauses=clauses,
        required_terms=req_terms,
        exclusion_terms=excl_terms,
        referenced_fields=ref_fields,
        active_lists=active_lists,
    )

