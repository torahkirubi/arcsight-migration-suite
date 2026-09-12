"""Headless batch validation for deterministic telemetry query compilation."""

from __future__ import annotations

import argparse
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, Iterable

from backend.schemas.exclusion_ir import RuleTuningAnalysis
from backend.telemetry_tuner import KQLQueryCompiler, validate_kql_syntax


def compile_rule(rule: Dict[str, Any]) -> Dict[str, Any]:
    """Compile one rule and return a machine-readable validation result."""
    try:
        query = str(rule["raw_kql"])
    except (KeyError, TypeError, ValueError) as exc:
        return {"id": rule.get("id"), "status": "schema_errors", "error": str(exc)}
    try:
        analysis = RuleTuningAnalysis.model_validate(rule["analysis"])
    except (KeyError, TypeError, ValueError) as exc:
        return {"id": rule.get("id"), "status": "schema_errors", "error": str(exc)}
    try:
        compiled = KQLQueryCompiler(query).render(analysis)
        validate_kql_syntax(compiled)
        return {"id": rule.get("id"), "status": "passed", "query": compiled}
    except (TypeError, ValueError) as exc:
        return {"id": rule.get("id"), "status": "failed", "error": str(exc)}


def compile_rules(rules: Iterable[Dict[str, Any]], workers: int = 4) -> Dict[str, Any]:
    """Compile rules concurrently and summarize passed, failed, and schema errors."""
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        results = list(pool.map(compile_rule, rules))
    return {
        "passed": sum(result["status"] == "passed" for result in results),
        "failed": sum(result["status"] == "failed" for result in results),
        "schema_errors": sum(result["status"] == "schema_errors" for result in results),
        "results": results,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="JSON file containing a list of rule definitions")
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args()
    payload = json.loads(args.input.read_text(encoding="utf-8"))
    rules = payload if isinstance(payload, list) else payload.get("rules", [])
    print(json.dumps(compile_rules(rules, workers=args.workers), indent=2))


if __name__ == "__main__":
    main()
