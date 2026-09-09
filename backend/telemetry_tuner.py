"""
telemetry_tuner.py - Dynamic threshold calculation and telemetry baseline tuning
"""

import math
from typing import Dict, Any


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

