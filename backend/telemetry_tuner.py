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


def apply_exclusions(raw_kql: Optional[str], entities: Optional[List[Any]]) -> str:
    """
    Injects a negative exclusion block for identified entities into a raw KQL query.

    If entities is empty, None, or raw_kql is empty, returns raw_kql unchanged.
    Locates the first instance of an aggregate function (| summarize or | count) and injects:
        | where Object !in ('entity1', 'entity2')
    immediately before the aggregate. If no aggregate function is found, cleanly appends
    the exclusion block to the end of the query.
    """
    if raw_kql is None:
        return ""
    if not isinstance(raw_kql, str) or not raw_kql.strip():
        return raw_kql
    if not entities:
        return raw_kql

    cleaned_entities = [str(e) for e in entities if e is not None and str(e).strip()]
    if not cleaned_entities:
        return raw_kql

    formatted_entities = ", ".join(f"'{e}'" for e in cleaned_entities)
    exclusion_clause = f"| where Object !in ({formatted_entities})"

    # Locate first instance of an aggregate function (| summarize or | count)
    match = re.search(r"(?i)(\|\s*(?:summarize|count)\b)", raw_kql)
    if match:
        idx = match.start()
        line_start = raw_kql.rfind("\n", 0, idx)
        if line_start != -1:
            indent = raw_kql[line_start + 1 : idx]
            if indent.strip() == "":
                return f"{raw_kql[:line_start + 1]}{indent}{exclusion_clause}\n{raw_kql[line_start + 1:]}"
            else:
                return f"{raw_kql[:idx]}{exclusion_clause}\n{raw_kql[idx:]}"
        else:
            if raw_kql[:idx].strip():
                return f"{raw_kql[:idx]}{exclusion_clause} {raw_kql[idx:]}"
            else:
                return f"{exclusion_clause}\n{raw_kql}"
    else:
        if "\n" in raw_kql:
            return f"{raw_kql.rstrip()}\n{exclusion_clause}"
        else:
            return f"{raw_kql.rstrip()} {exclusion_clause}"

