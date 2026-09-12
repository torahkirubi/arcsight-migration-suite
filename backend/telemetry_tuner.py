"""
telemetry_tuner.py - Dynamic threshold calculation and telemetry baseline tuning
"""

import math
import re
from typing import Dict, Any, List, Optional


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
}
SUPPORTED_ENTITY_FIELDS = frozenset(CANONICAL_FIELDS.values())


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
    """
    Injects negative exclusion blocks for identified entities into a raw KQL query.

    Normalizes entities (dictionaries, stringified dictionaries, or plain strings):
    - Single-key dicts and primitives are grouped by column: | where <Field> !in ('val1', 'val2')
    - Multi-key compound dicts generate compound clauses: | where not (<field1> == 'v1' and <field2> has 'v2')
    Injected immediately before aggregate clauses (| summarize or | count) or appended cleanly.
    """
    if raw_kql is None:
        return ""
    if not isinstance(raw_kql, str) or not raw_kql.strip():
        return raw_kql
    if not entities:
        return raw_kql

    grouped_single_exclusions: Dict[str, List[str]] = {}
    compound_clauses: List[str] = []

    def _add_single_pair(f: str, v: str):
        if f not in grouped_single_exclusions:
            grouped_single_exclusions[f] = []
        if v not in grouped_single_exclusions[f]:
            grouped_single_exclusions[f].append(v)

    def _process_dict(d: Dict[str, Any]):
        if "field" in d and "value" in d and len(d) == 2:
            pair = _normalize_entity_pair(str(d["field"]), d["value"])
            if pair:
                _add_single_pair(pair[0], pair[1])
        elif "name" in d and "type" in d and len(d) == 2:
            pair = _normalize_entity_pair(str(d["type"]), d["name"])
            if pair:
                _add_single_pair(pair[0], pair[1])
        elif len(d) == 1:
            for k, v in d.items():
                if isinstance(v, (list, tuple, set)):
                    for sub_v in v:
                        pair = _normalize_entity_pair(str(k), sub_v)
                        if pair:
                            _add_single_pair(pair[0], pair[1])
                else:
                    pair = _normalize_entity_pair(str(k), v)
                    if pair:
                        _add_single_pair(pair[0], pair[1])
        elif len(d) > 1:
            clause = _format_compound_dict_clause(d)
            if clause and clause not in compound_clauses:
                compound_clauses.append(clause)

    for item in entities:
        if item is None:
            continue

        # Handle dictionaries directly
        if isinstance(item, dict):
            _process_dict(item)
            continue

        # Handle string or primitive item
        str_item = str(item).strip()
        if not str_item:
            continue

        labeled = _parse_labeled_entity(str_item)
        if labeled:
            _add_single_pair(labeled["field"], labeled["value"])
            continue

        # Defensive unpacking for stringified dictionaries (e.g. "{'AccountName': 'svc-scanner'}")
        if str_item.startswith("{") and str_item.endswith("}"):
            parsed_dict = None
            try:
                import ast
                parsed = ast.literal_eval(str_item)
                if isinstance(parsed, dict):
                    parsed_dict = parsed
            except Exception:
                pass
            if parsed_dict is None:
                try:
                    import json
                    parsed = json.loads(str_item)
                    if isinstance(parsed, dict):
                        parsed_dict = parsed
                except Exception:
                    pass

            if isinstance(parsed_dict, dict):
                _process_dict(parsed_dict)
                continue

        # Plain string entity: resolve field using heuristics / target_field
        effective_field = target_field
        if effective_field == "Computer":
            has_account_field = bool(re.search(r"\bAccountName\b", raw_kql, re.IGNORECASE))
            looks_like_account = bool(re.search(
                r"^(?:svc[-_]|adm[-_]|user[-_]|service|admin|[a-z0-9._%+-]+@|[a-z0-9._-]+\\)",
                str_item,
                re.IGNORECASE,
            ))
            if has_account_field and (looks_like_account or not re.search(r"\bComputer\b", raw_kql, re.IGNORECASE)):
                effective_field = "AccountName"

        pair = _normalize_entity_pair(effective_field, str_item)
        if pair:
            _add_single_pair(pair[0], pair[1])

    # Build ordered list of exclusion clauses
    clauses: List[str] = []
    for field, values in grouped_single_exclusions.items():
        formatted_vals = ", ".join(f"'{v}'" for v in values)
        clauses.append(f"| where {field} !in ({formatted_vals})")
    for cc in compound_clauses:
        if cc not in clauses:
            clauses.append(cc)

    if not clauses:
        return raw_kql

    # Locate first instance of an aggregate function (| summarize or | count)
    match = re.search(r"(?i)(\|\s*(?:summarize|count)\b)", raw_kql)
    if match:
        idx = match.start()
        line_start = raw_kql.rfind("\n", 0, idx)
        if line_start != -1:
            indent = raw_kql[line_start + 1 : idx]
            if indent.strip() == "":
                indented_block = "\n".join(f"{indent}{c}" for c in clauses)
                return f"{raw_kql[:line_start + 1]}{indented_block}\n{raw_kql[line_start + 1:]}"
            else:
                block = "\n".join(clauses)
                return f"{raw_kql[:idx]}{block}\n{raw_kql[idx:]}"
        else:
            if raw_kql[:idx].strip():
                joined_clauses = " ".join(clauses)
                return f"{raw_kql[:idx]}{joined_clauses} {raw_kql[idx:]}"
            else:
                block = "\n".join(clauses)
                return f"{block}\n{raw_kql}"
    else:
        if "\n" in raw_kql:
            block = "\n".join(clauses)
            return f"{raw_kql.rstrip()}\n{block}"
        else:
            joined_clauses = " ".join(clauses)
            return f"{raw_kql.rstrip()} {joined_clauses}"
