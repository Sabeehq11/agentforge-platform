#!/usr/bin/env python3
"""P3 suite checks. No network. Exit 1 if a case is invalid, a fixture has a PHI pattern, or a dry-run fabricates a pass."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentforge.evals.cases import CaseRejected, load_cases  # noqa: E402
from agentforge.evals.executor import run_dry  # noqa: E402
from agentforge.safety.budget import Budget, Caps, approval_token  # noqa: E402
from agentforge.safety.phi import scan  # noqa: E402


def main() -> int:
    problems: list[str] = []
    fixtures = ROOT / "evals" / "fixtures"
    for path in sorted(fixtures.glob("*")):
        if not path.is_file():
            continue
        kinds = scan(path.read_text(encoding="utf-8"))
        if kinds:
            problems.append(f"{path.name} phi: {', '.join(kinds)}")
    try:
        cases = load_cases()
    except (CaseRejected, OSError) as exc:
        print(f"FAIL {exc}")
        return 1
    categories = {case.category for case in cases}
    if len(categories) < 3:
        problems.append(f"need 3 categories, found {sorted(categories)}")
    for case in cases:
        if case.exercise not in {"boundary", "invariant", "regression_risk"}:
            problems.append(f"{case.case_id} missing exercise tag")
        if not case.owasp_id:
            problems.append(f"{case.case_id} missing owasp id")
    bare = run_dry(cases)
    for item in bare:
        if item.outcome == "pass":
            problems.append(f"{item.case_id} dry-run fabricated a pass")
        if item.outcome != "not_run":
            problems.append(f"{item.case_id} unexpected dry-run outcome {item.outcome}")
    caps = Caps(1.0, 1.0, 1, 5.0, 5.0)
    budget = Budget(caps)
    budget.approve(approval_token(caps, "suite-check-not-a-credential"), "suite-check-not-a-credential")
    graded = {item.case_id: item for item in run_dry(cases, budget=budget)}
    cap_case = next(case for case in cases if case.grader == "attack_count")
    if graded[cap_case.case_id].outcome != "not_run":
        problems.append("attack-count local cap stop was graded")
    for case in cases:
        if graded[case.case_id].outcome != "not_run":
            problems.append(f"{case.case_id} dry-run was not not_run")
    if problems:
        print("FAIL")
        for problem in problems:
            print(f"  {problem}")
        return 1
    print(f"OK {len(cases)} cases, categories {sorted(categories)}, dry-run fabricated no pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
