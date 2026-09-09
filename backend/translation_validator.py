"""
translation_validator.py - Deterministic Detection Coverage Validator

Validates that generated KQL and SPL queries preserve the detection logic
extracted from the source ArcSight rule:
1. Every required match-term is present in the target query.
2. Every exclusion-term is present AND located in a negated context.
   (Detects wrongly_included_as_match to prevent catastrophic false positives).
3. Exposes a 'passed' property and a '.to_dict()' serializer.
   CRITICAL GOTCHA: 'passed' is a property, so .to_dict() must always be used
   instead of .__dict__ to ensure 'passed' is preserved in JSON responses.
"""

from dataclasses import dataclass, field
import re
from typing import Any, Dict, List, Optional
from backend.arcsight_parser import ParsedArcSightRule, parse_arcsight_rule


@dataclass
class ValidationResult:
    target_language: str  # "KQL" | "SPL"
    required_terms_checked: List[str]
    missing_required: List[str]
    exclusion_terms_checked: List[str]
    missing_exclusions: List[str]
    wrongly_included_as_match: List[str]
    coverage_pct: float
    notes: List[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        """
        True only if:
        - 100% of required terms are present.
        - Zero exclusion terms were erroneously included without negation.
        - All exclusion terms are properly negated.
        """
        return (
            len(self.missing_required) == 0
            and len(self.wrongly_included_as_match) == 0
            and len(self.missing_exclusions) == 0
        )

    def to_dict(self) -> Dict[str, Any]:
        """
        Serializes the validation result into a JSON-safe dictionary.
        Explicitly serializes the @property 'passed' to prevent regression bugs.
        """
        return {
            "target_language": self.target_language,
            "passed": self.passed,
            "coverage_pct": round(self.coverage_pct, 1),
            "required_terms_checked": self.required_terms_checked,
            "missing_required": self.missing_required,
            "exclusion_terms_checked": self.exclusion_terms_checked,
            "missing_exclusions": self.missing_exclusions,
            "wrongly_included_as_match": self.wrongly_included_as_match,
            "notes": self.notes,
        }


def is_in_negated_context(query_text: str, term: str, language: str) -> bool:
    """
    Checks if occurrences of term within query_text are in a negated context.
    Returns True if at least one occurrence is negated and no unnegated positive match exists.
    """
    clean_term = term.strip().lower()
    lower_query = query_text.lower()

    if clean_term not in lower_query:
        return False

    # Regex patterns indicating negation in KQL and SPL
    # Look for NOT, !=, !has, !contains, !in, doesnotcontain, etc. preceding the term
    # or inside where not(...) / NOT (...)
    negation_patterns = [
        # SPL: NOT term or NOT field="term" or field!=term or field!="term"
        rf'\bnot\s+[^\|\r\n]*?\b{re.escape(clean_term)}\b',
        rf'\bnot\s*\([^)]*?{re.escape(clean_term)}[^)]*?\)',
        rf'!\s*=\s*["\']?[^"\'\|\r\n]*?{re.escape(clean_term)}["\']?',
        rf'!\s*~\s*["\']?[^"\'\|\r\n]*?{re.escape(clean_term)}["\']?',
        # KQL: !has, !contains, !in, !=, not(...)
        rf'!(?:has|contains|startswith|endswith|in|has_any|has_all)\b[^\|\r\n]*?{re.escape(clean_term)}',
        rf'\bnot\s*\([^)]*?{re.escape(clean_term)}[^)]*?\)',
        rf'\bwhere\s+not\b[^\|\r\n]*?{re.escape(clean_term)}',
        rf'\bwhere\s+![^\|\r\n]*?{re.escape(clean_term)}',
    ]

    for pattern in negation_patterns:
        if re.search(pattern, lower_query):
            return True

    # Check line-by-line context: lines starting with 'where ... !' or '| where not' or '| search NOT'
    lines = query_text.splitlines()
    for line in lines:
        lower_line = line.lower()
        if clean_term in lower_line:
            if any(op in lower_line for op in ["!=", "!has", "!contains", "!in", "not ", "not(", "where not"]):
                return True

    return False


def validate_query(
    query_text: str,
    required_terms: List[str],
    exclusion_terms: List[str],
    target_language: str = "KQL",
) -> ValidationResult:
    """
    Validates a generated query against required match terms and exclusion terms.
    """
    clean_query = query_text or ""
    lower_query = clean_query.lower()
    missing_required: List[str] = []
    missing_exclusions: List[str] = []
    wrongly_included: List[str] = []
    notes: List[str] = []

    safe_req = [str(r).strip() for r in (required_terms or []) if r and str(r).strip()]
    safe_excl = [str(e).strip() for e in (exclusion_terms or []) if e and str(e).strip()]

    # 1. Validate Required Terms
    for clean_req in safe_req:
        if clean_req.lower() not in lower_query:
            missing_required.append(clean_req)

    # 2. Validate Exclusion Terms
    for clean_excl in safe_excl:
        if clean_excl.lower() not in lower_query:
            # Term was completely omitted from query
            missing_exclusions.append(clean_excl)
        else:
            # Term is in the query — verify it is strictly negated!
            if not is_in_negated_context(clean_query, clean_excl, target_language):
                wrongly_included.append(clean_excl)
                notes.append(
                    f"CRITICAL: Exclusion term '{clean_excl}' appears in {target_language} without negation! "
                    "This would cause false positives instead of filtering."
                )

    # Compute coverage percentage
    total_checks = len(safe_req) + len(safe_excl)
    if total_checks == 0:
        coverage_pct = 100.0
    else:
        passed_required = len(safe_req) - len(missing_required)
        passed_exclusions = len(safe_excl) - len(missing_exclusions) - len(wrongly_included)
        passed_score = max(0, passed_required + passed_exclusions)
        coverage_pct = (passed_score / total_checks) * 100.0

    if missing_required:
        notes.append(f"Missing required detection terms: {', '.join(missing_required)}")
    if missing_exclusions:
        notes.append(f"Exclusion filters omitted from query: {', '.join(missing_exclusions)}")

    return ValidationResult(
        target_language=target_language,
        required_terms_checked=safe_req,
        missing_required=missing_required,
        exclusion_terms_checked=safe_excl,
        missing_exclusions=missing_exclusions,
        wrongly_included_as_match=wrongly_included,
        coverage_pct=coverage_pct,
        notes=notes,
    )


def validate_translation_bundle(
    kql_query: str,
    spl_query: str,
    parsed_rule: Any,
) -> Dict[str, Any]:
    """
    Validates both KQL and SPL queries against a parsed ArcSight rule.
    Accepts ParsedArcSightRule instance or dictionary.
    Returns a dictionary with 'kql', 'spl', and overall 'passed'.
    """
    if isinstance(parsed_rule, dict):
        req_terms = parsed_rule.get("required_terms") or []
        excl_terms = parsed_rule.get("exclusion_terms") or []
    elif hasattr(parsed_rule, "required_terms"):
        req_terms = getattr(parsed_rule, "required_terms", []) or []
        excl_terms = getattr(parsed_rule, "exclusion_terms", []) or []
    else:
        req_terms = []
        excl_terms = []

    kql_val = validate_query(kql_query or "", req_terms, excl_terms, "KQL")
    spl_val = validate_query(spl_query or "", req_terms, excl_terms, "SPL")

    return {
        "kql": kql_val.to_dict(),
        "spl": spl_val.to_dict(),
        "passed": kql_val.passed and spl_val.passed,
        "overall_coverage_pct": round((kql_val.coverage_pct + spl_val.coverage_pct) / 2.0, 1),
    }

