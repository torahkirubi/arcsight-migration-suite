---
trigger: always_on
description: Enforce strict Test-Driven Development (TDD) workflow, deterministic exclusion parity, and automated test execution across the workspace.
---

# Strict Test-Driven Development (TDD) Rules

## 1. Test-First Requirement
Always write or update unit tests in `backend/tests/` and verify they fail before writing or modifying any implementation code in `backend/`. Never introduce implementation logic without a pre-existing failing test proving the requirement.

## 2. Deterministic Parity
Any detection translation work (SPL or KQL) must explicitly test for negative logic retention (`NOT`, `!=`, `!has`, `!has_any`). Ensure that exclusion filters and negation operators are strictly preserved and never inverted into inclusive matches.

## 3. Verification Step
Run `python3 -m unittest discover -s backend/tests` after every code modification and report the outcome.

