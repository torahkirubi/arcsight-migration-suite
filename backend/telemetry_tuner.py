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


def apply_exclusions(
    raw_kql: Optional[str],
    entities: Optional[List[Any]],
    target_field: str = "Computer",
) -> str:
    """
    Injects negative exclusion blocks for identified entities into a raw KQL query.

    Normalizes entities (dictionaries, stringified dictionaries, or plain strings)
    into column-specific groups and generates clean clauses:
        | where <Field> !in ('val1', 'val2')
    injected immediately before aggregate clauses (| summarize or | count) or appended cleanly.
    """
    if raw_kql is None:
        return ""
    if not isinstance(raw_kql, str) or not raw_kql.strip():
        return raw_kql
    if not entities:
        return raw_kql

    grouped_exclusions: Dict[str, List[str]] = {}

    def _add_pair(f: str, v: str):
        if f not in grouped_exclusions:
            grouped_exclusions[f] = []
        if v not in grouped_exclusions[f]:
            grouped_exclusions[f].append(v)

    for item in entities:
        if item is None:
            continue

        # Handle dictionaries directly
        if isinstance(item, dict):
            # Check for {"field": ..., "value": ...} pattern
            if "field" in item and "value" in item:
                pair = _normalize_entity_pair(str(item["field"]), item["value"])
                if pair:
                    _add_pair(pair[0], pair[1])
            elif "name" in item and "type" in item:
                pair = _normalize_entity_pair(str(item["type"]), item["name"])
                if pair:
                    _add_pair(pair[0], pair[1])
            else:
                for k, v in item.items():
                    if isinstance(v, (list, tuple, set)):
                        for sub_v in v:
                            pair = _normalize_entity_pair(str(k), sub_v)
                            if pair:
                                _add_pair(pair[0], pair[1])
                    else:
                        pair = _normalize_entity_pair(str(k), v)
                        if pair:
                            _add_pair(pair[0], pair[1])
            continue

        # Handle string or primitive item
        str_item = str(item).strip()
        if not str_item:
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
                for k, v in parsed_dict.items():
                    if isinstance(v, (list, tuple, set)):
                        for sub_v in v:
                            pair = _normalize_entity_pair(str(k), sub_v)
                            if pair:
                                _add_pair(pair[0], pair[1])
                    else:
                        pair = _normalize_entity_pair(str(k), v)
                        if pair:
                            _add_pair(pair[0], pair[1])
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
            _add_pair(pair[0], pair[1])

    if not grouped_exclusions:
        return raw_kql

    # Build individual column exclusion clauses
    clauses: List[str] = []
    for field, values in grouped_exclusions.items():
        formatted_vals = ", ".join(f"'{v}'" for v in values)
        clauses.append(f"| where {field} !in ({formatted_vals})")

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


