"""
telemetry_tuner.py - Dynamic threshold calculation and telemetry baseline tuning
"""

import math
import re
from typing import Dict, Any, List, Optional, Sequence, Tuple

from backend.schemas.exclusion_ir import (
    CompoundExclusion,
    RuleTuningAnalysis,
    SingleFieldExclusion,
)


def calculate_dynamic_threshold(
    baseline_event_count: int,
    static_rule_threshold: int,
    buffer_pct: float = 0.20,
) -> Dict[str, Any]:
    """
    Evaluates historical baseline volume against the static rule threshold.
    If baseline noise exceeds the static threshold, calculates a suggested threshold
    safely above baseline noise (e.g. baseline + 20% buffer rounded up).
    Otherwise returns the original static threshold.
    """
    original_threshold = int(static_rule_threshold)
    baseline_count = int(baseline_event_count)

    if baseline_count > original_threshold:
        buffer = math.ceil(baseline_count * buffer_pct)
        if buffer == 0:
            buffer = 1
        suggested_threshold = baseline_count + buffer
        tuning_rationale = (
            f"Historical baseline returned {baseline_count} events over the evaluation window, "
            f"exceeding the static threshold of {original_threshold}. Elevated threshold to "
            f"{suggested_threshold} (+{int(buffer_pct * 100)}% buffer: +{buffer} events) to suppress false positives."
        )
    else:
        suggested_threshold = original_threshold
        tuning_rationale = (
            f"Historical baseline returned {baseline_count} events, which is within the static "
            f"threshold of {original_threshold}. Preserving original rule threshold."
        )

    return {
        "original_threshold": original_threshold,
        "suggested_threshold": suggested_threshold,
        "tuning_rationale": tuning_rationale,
    }


CANONICAL_FIELDS: Dict[str, str] = {
    "accountname": "AccountName",
    "account": "AccountName",
    "username": "AccountName",
    "user": "AccountName",
    "targetaccount": "TargetAccount",
    "computer": "Computer",
    "computername": "Computer",
    "hostname": "Computer",
    "processname": "ProcessName",
    "process": "ProcessName",
    "commandline": "CommandLine",
    "command": "CommandLine",
    "eventid": "EventID",
    "ipaddress": "IpAddress",
    "devicename": "DeviceName",
    "filename": "FileName",
    "processcommandline": "ProcessCommandLine",
    "userprincipalname": "UserPrincipalName",
    "appdisplayname": "AppDisplayName",
    "sourceusername": "SourceUserName",
    "sourceip": "SourceIP",
    "destinationip": "DestinationIP",
}
SUPPORTED_ENTITY_FIELDS = frozenset(CANONICAL_FIELDS.values())

TABLE_SCHEMA_REGISTRY: Dict[str, frozenset[str]] = {
    "securityevents_cl": frozenset({"AccountName", "Computer", "ProcessName", "CommandLine", "EventID", "IpAddress"}),
    "securityevent": frozenset({"AccountName", "Computer", "ProcessName", "CommandLine", "EventID", "IpAddress", "TargetAccount"}),
    "deviceprocessevents": frozenset({"AccountName", "DeviceName", "FileName", "ProcessCommandLine", "ProcessName"}),
    "signinlogs": frozenset({"UserPrincipalName", "IPAddress", "IpAddress", "AppDisplayName"}),
    "commonsignallog": frozenset({"SourceUserName", "DeviceName", "SourceIP", "DestinationIP"}),
}


def table_schema(table: str) -> frozenset[str]:
    """Return the allowlisted columns for a known Log Analytics table."""
    return TABLE_SCHEMA_REGISTRY.get(table.strip().lower(), frozenset())


def _query_table(raw_kql: str) -> str:
    match = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)", raw_kql or "")
    return match.group(1) if match else ""


def resolve_field(field: str, raw_kql: str = "") -> Optional[str]:
    """Canonicalize a field and validate it against the query's known table."""
    canonical = CANONICAL_FIELDS.get(field.strip().lower(), field.strip())
    if not canonical:
        return None
    schema = table_schema(_query_table(raw_kql))
    if schema and canonical not in schema:
        return None
    return canonical


class KQLQueryCompiler:
    """Render validated exclusion IR into deterministic KQL pipeline clauses."""

    def __init__(self, raw_kql: str, default_target_field: str = "Computer"):
        self.raw_kql = raw_kql
        self.schema = table_schema(_query_table(raw_kql))
        self.default_target_field = default_target_field

    def _field(self, value: str) -> str:
        field = resolve_field(value, self.raw_kql)
        if not field:
            raise ValueError(f"Field {value!r} is not allowed for {_query_table(self.raw_kql) or 'query'}")
        return field

    @staticmethod
    def _quote(value: str) -> str:
        return "'" + str(value).replace(r"\'", "'").replace("'", r"\'") + "'"

    def render(self, analysis: RuleTuningAnalysis | Sequence[Any]) -> str:
        structured_sequence = (
            isinstance(analysis, (list, tuple))
            and all(isinstance(item, (SingleFieldExclusion, CompoundExclusion)) for item in analysis)
        )
        legacy_mode = not isinstance(analysis, RuleTuningAnalysis) and not structured_sequence
        if isinstance(analysis, RuleTuningAnalysis):
            exclusions = analysis.exclusions
        elif structured_sequence:
            exclusions = analysis
        else:
            exclusions = self._legacy_exclusions(analysis)
        clauses: List[str] = []
        for exclusion in exclusions or []:
            if isinstance(exclusion, dict):
                if exclusion.get("type") == "single_field":
                    exclusion = SingleFieldExclusion(**exclusion)
                elif exclusion.get("type") == "compound":
                    exclusion = CompoundExclusion(**exclusion)
            if isinstance(exclusion, SingleFieldExclusion):
                field = resolve_field(str(exclusion.field), self.raw_kql) if legacy_mode else self._field(exclusion.field)
                if legacy_mode and not field:
                    field = CANONICAL_FIELDS.get(str(exclusion.field).lower(), str(exclusion.field))
                if not field:
                    continue
                values = ", ".join(self._quote(v) for v in exclusion.values)
                if exclusion.operator == "!in":
                    clauses.append(f"| where {field} !in ({values})")
                else:
                    clauses.extend(f"| where {field} {exclusion.operator} {self._quote(v)}" for v in exclusion.values)
            else:
                conditions = []
                for condition in exclusion.conditions:
                    condition_field = condition.get("field") if isinstance(condition, dict) else condition.field
                    condition_operator = condition.get("operator") if isinstance(condition, dict) else condition.operator
                    condition_value = condition.get("value") if isinstance(condition, dict) else condition.value
                    field = resolve_field(str(condition_field), self.raw_kql) if legacy_mode else self._field(condition_field)
                    if legacy_mode and not field:
                        field = CANONICAL_FIELDS.get(str(condition_field).lower(), str(condition_field))
                    if not field:
                        continue
                    operator = "has" if condition_operator == "contains" else condition_operator
                    conditions.append(f"{field} {operator} {self._quote(condition_value)}")
                clauses.append(f"| where not ({' and '.join(conditions)})")
        return self._insert(clauses)

    def _legacy_exclusions(self, entities: Sequence[Any]) -> List[Any]:
        grouped: Dict[str, List[str]] = {}
        compounds: List[CompoundExclusion] = []
        for item in entities:
            if isinstance(item, str) and item.strip().startswith(("{", "[")):
                try:
                    import ast
                    parsed = ast.literal_eval(item)
                    if isinstance(parsed, dict):
                        item = parsed
                except (SyntaxError, ValueError):
                    try:
                        import json
                        parsed = json.loads(item)
                        if isinstance(parsed, dict):
                            item = parsed
                    except (json.JSONDecodeError, TypeError):
                        pass
            if isinstance(item, dict) and len(item) > 1 and "field" not in item:
                conditions = [
                    {"field": key, "operator": "contains" if "command" in key.lower() else "==", "value": str(value)}
                    for key, value in item.items() if value is not None
                ]
                if len(conditions) >= 2:
                    compounds.append(CompoundExclusion(conditions=conditions))
                continue
            if isinstance(item, dict):
                field = item.get("field") or item.get("type") or next(iter(item), None)
                value = item.get("value") if "value" in item else item.get(field)
            else:
                labeled = _parse_labeled_entity(item)
                if labeled:
                    field, value = labeled["field"], labeled["value"]
                else:
                    field, value = None, item
            if field is None:
                field = self._legacy_target_field()
            canonical = resolve_field(str(field), self.raw_kql) or CANONICAL_FIELDS.get(
                str(field).lower(), str(field)
            )
            if canonical and value is not None:
                grouped.setdefault(canonical, []).extend(
                    str(v) for v in (value if isinstance(value, (list, tuple, set)) else [value]) if str(v).strip()
                )
        exclusions: List[Any] = [
            SingleFieldExclusion(field=field, values=list(dict.fromkeys(values)))
            for field, values in grouped.items()
        ]
        return exclusions + compounds

    def _legacy_target_field(self) -> str:
        if self.default_target_field != "Computer":
            return self.default_target_field
        if self.schema:
            candidates = [field for field in ("Computer", "AccountName", "ProcessName") if field in self.schema]
            mentioned = [field for field in candidates if re.search(rf"\b{re.escape(field)}\b", self.raw_kql, re.I)]
            if candidates:
                if "Computer" not in mentioned and "AccountName" in mentioned:
                    return "AccountName"
                return mentioned[0] if mentioned else candidates[0]
        return self.default_target_field

    def _insert(self, clauses: List[str]) -> str:
        if not clauses:
            return self.raw_kql
        block = "\n".join(clauses)
        match = re.search(r"(?i)(\|\s*(?:summarize|count|top)\b)", self.raw_kql)
        if not match:
            return f"{self.raw_kql.rstrip()}\n{block}" if "\n" in self.raw_kql else f"{self.raw_kql.rstrip()} {block}"
        line_start = self.raw_kql.rfind("\n", 0, match.start())
        insertion = match.start() if line_start == -1 else line_start + 1
        return f"{self.raw_kql[:insertion]}{block}\n{self.raw_kql[insertion:]}"


def validate_kql_syntax(query: str) -> None:
    """Run parser-independent structural checks before a query is submitted."""
    if not isinstance(query, str) or not query.strip():
        raise ValueError("KQL query is empty")
    if not re.match(r"\s*[A-Za-z_][A-Za-z0-9_]*", query):
        raise ValueError("KQL query must start with a table identifier")
    paren_depth = 0
    in_string = False
    escaped = False
    for char in query:
        if char == "\\" and in_string and not escaped:
            escaped = True
            continue
        if char == "'" and not escaped:
            in_string = not in_string
        if not in_string:
            if char == "(":
                paren_depth += 1
            elif char == ")":
                paren_depth -= 1
                if paren_depth < 0:
                    raise ValueError("KQL query has an unmatched closing parenthesis")
        escaped = False
    if in_string or paren_depth:
        raise ValueError("KQL query has unbalanced quotes or parentheses")


def _parse_labeled_entity(value: Any) -> Optional[Dict[str, str]]:
    """Parse an explicit `Field: Value` entity without guessing its column."""
    if not isinstance(value, str) or ":" not in value:
        return None
    field_name, entity_value = value.split(":", 1)
    pair = _normalize_entity_pair(field_name.strip(), entity_value.strip())
    if not pair or pair[0] not in SUPPORTED_ENTITY_FIELDS:
        return None
    return {"field": pair[0], "value": pair[1]}


def normalize_structured_entities(entities: Any) -> List[Dict[str, str]]:
    """Accept only explicit field/value objects for safe KQL generation."""
    if not isinstance(entities, list):
        return []

    normalized: List[Dict[str, str]] = []
    for entity in entities:
        labeled = _parse_labeled_entity(entity)
        if labeled:
            normalized.append(labeled)
            continue
        if not isinstance(entity, dict):
            continue
        if "field" in entity and "value" in entity:
            pair = _normalize_entity_pair(str(entity["field"]), entity["value"])
            if pair and pair[0] in SUPPORTED_ENTITY_FIELDS:
                normalized.append({"field": pair[0], "value": pair[1]})
            continue
        if len(entity) == 1:
            key, value = next(iter(entity.items()))
            pair = _normalize_entity_pair(str(key), value)
            if pair and pair[0] in SUPPORTED_ENTITY_FIELDS:
                normalized.append({"field": pair[0], "value": pair[1]})
            continue
        if len(entity) > 1 and all(str(key) in SUPPORTED_ENTITY_FIELDS for key in entity):
            compound = {
                CANONICAL_FIELDS[str(key).lower()]: str(value).strip().replace(r"\'", "'").replace("'", r"\'")
                for key, value in entity.items()
                if value is not None and str(value).strip()
            }
            if compound:
                normalized.append(compound)
    return normalized


def _normalize_entity_pair(field_name: str, val: Any) -> Optional[tuple]:
    if val is None:
        return None
    s_val = str(val).strip()
    if not s_val:
        return None
    canon_field = CANONICAL_FIELDS.get(field_name.lower(), field_name.strip())
    # Cleanly escape single quotes without double-escaping
    clean_val = s_val.replace(r"\'", "'").replace("'", r"\'")
    return canon_field, clean_val


def _format_compound_dict_clause(d: Dict[str, Any]) -> Optional[str]:
    """Generates a compound negative expression: | where not (<cond1> and <cond2>)."""
    conds = []
    for k, v in d.items():
        if v is None:
            continue
        canon_field = CANONICAL_FIELDS.get(str(k).strip().lower(), str(k).strip())
        clean_val = str(v).strip().replace(r"\'", "'").replace("'", r"\'")
        if not clean_val:
            continue
        # Use `has` for command line fields and `==` for exact entity fields
        if canon_field.lower() in ("commandline", "command") or "command" in canon_field.lower():
            conds.append(f"{canon_field} has '{clean_val}'")
        else:
            conds.append(f"{canon_field} == '{clean_val}'")
    if conds:
        return f"| where not ({' and '.join(conds)})"
    return None


def apply_exclusions(
    raw_kql: Optional[str],
    entities: Optional[List[Any]],
    target_field: str = "Computer",
) -> str:
    """Compile structured or legacy entities into deterministic KQL exclusions."""
    if raw_kql is None:
        return ""
    if not isinstance(raw_kql, str) or not raw_kql.strip():
        return raw_kql
    if not entities:
        return raw_kql
    compiler = KQLQueryCompiler(raw_kql, default_target_field=target_field)
    return compiler.render(entities)
