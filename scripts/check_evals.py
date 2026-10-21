#!/usr/bin/env python3
"""P3 suite checks. No network. Exit 1 if a case is invalid, a fixture has a PHI pattern, or a dry-run fabricates a pass."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentforge.evals.cases import Case, CaseRejected, load_cases  # noqa: E402
from agentforge.evals.executor import run_dry  # noqa: E402
from agentforge.evals.ledger import check_ledger, llm08_wording_problems, load_ledger  # noqa: E402
from agentforge.evals.offline import RESULT_PATH, evaluate_case, load_pairs, suite_problems  # noqa: E402
from agentforge.safety.budget import Budget, Caps, approval_token  # noqa: E402
from agentforge.safety.phi import scan  # noqa: E402


def _ledger_and_gate(cases: tuple[Case, ...]) -> list[str]:
    """Ledger, p.11 validity gate for every case, offline outcomes and LLM08 wording. Every case is checked."""
    problems: list[str] = []
    ledger = load_ledger()
    problems.extend(f"ledger: {item}" for item in check_ledger(ledger, cases))
    pairs = load_pairs()
    problems.extend(f"p11 suite: {item}" for item in suite_problems(cases, pairs))
    for case in cases:
        verdict = evaluate_case(case, pairs)
        for name in verdict.failed:
            problems.append(f"p11 gate {case.case_id} {name}: {verdict.checks[name]}")
    stored: set[str] = set()
    campaign = ROOT / "evals" / "results" / "campaign-latest.json"
    if campaign.is_file():
        stored |= {str(row["case_id"]) for row in json.loads(campaign.read_text(encoding="utf-8")).get("results", [])}
    offline_rows: list[dict[str, object]] = []
    if RESULT_PATH.is_file():
        offline = json.loads(RESULT_PATH.read_text(encoding="utf-8"))
        if offline.get("live") is not False or offline.get("target_result") is not False:
            problems.append("offline-latest.json claims live or a target result")
        offline_rows = list(offline.get("results", []))
        stored |= {str(row["case_id"]) for row in offline_rows}
    else:
        problems.append("offline-latest.json is missing")
    for case in cases:
        if case.case_id not in stored:
            problems.append(f"{case.case_id} has no stored outcome in campaign-latest.json or offline-latest.json")
    for row in offline_rows:
        if row.get("safe_replay") != "pass" or row.get("weakened_replay") != "fail":
            problems.append(f"offline row {row.get('case_id')} does not discriminate")
    texts = {
        str(path.relative_to(ROOT)): path.read_text(encoding="utf-8")
        for path in [
            ROOT / "evals" / "owasp_coverage.json",
            RESULT_PATH,
            ROOT / "evals" / "offline" / "responses.json",
            *sorted((ROOT / "evals" / "cases").glob("*.json")),
        ]
        if path.is_file()
    }
    problems.extend(llm08_wording_problems(texts))
    return problems


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
    problems.extend(_ledger_and_gate(cases))
    if problems:
        print("FAIL")
        for problem in problems:
            print(f"  {problem}")
        return 1
    print(
        f"OK {len(cases)} cases, categories {sorted(categories)}, dry-run fabricated no pass, "
        "ledger consistent, p.11 gate passed on every case"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
