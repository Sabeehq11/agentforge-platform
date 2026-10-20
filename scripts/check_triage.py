#!/usr/bin/env python3
"""Triage-lab check. Exit 1 if the simulated report is missing a class, a field, or a required contradiction.

No network. Does not import the chokepoint. Does not open a socket.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

CLASSES = frozenset({"critical", "high", "medium", "false_positive"})
CATEGORIES = frozenset({"TM-PI", "TM-EX", "TM-SC", "TM-TM", "TM-DS", "TM-ID"})
DISPOSITIONS = frozenset({"validate", "remediate", "defer", "document"})
RESULTS = frozenset({"supported", "contradicted", "not_checkable_offline"})
ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "evals" / "triage" / "scan-report.json"


def check(path: Path) -> list[str]:
    problems: list[str] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"unreadable report: {exc}"]
    findings = data.get("findings")
    if not isinstance(findings, list) or len(findings) < 10:
        problems.append(f"expected at least 10 findings, found {len(findings) if isinstance(findings, list) else 0}")
        return problems
    seen = {item.get("class") for item in findings if isinstance(item, dict)}
    for required in CLASSES:
        if required not in seen:
            problems.append(f"missing class {required}")
    for item in findings:
        if not isinstance(item, dict):
            problems.append("finding is not an object")
            continue
        name = str(item.get("id") or "?")
        if item.get("simulated") is not True:
            problems.append(f"{name} simulated is not true")
        if item.get("class") not in CLASSES:
            problems.append(f"{name} class is not one of the four")
        if item.get("category") not in CATEGORIES:
            problems.append(f"{name} category is not in the threat model")
        evidence = item.get("validation_evidence")
        result = evidence.get("result") if isinstance(evidence, dict) else None
        checked = evidence.get("checked") if isinstance(evidence, dict) else ""
        if result not in RESULTS or not str(checked).strip():
            problems.append(f"{name} validation_evidence is incomplete")
        disposition = item.get("disposition")
        if disposition not in DISPOSITIONS:
            problems.append(f"{name} disposition is missing")
        rationale = str(item.get("rationale") or "")
        action = str(item.get("next_action") or "")
        if not rationale.strip() or not action.strip():
            problems.append(f"{name} rationale or next_action is blank")
        if result and result not in rationale:
            problems.append(f"{name} rationale does not mention the evidence result")
        if item.get("class") == "false_positive" and result != "contradicted":
            problems.append(f"{name} false positive is not contradicted")
        if disposition == "validate" and result == "not_checkable_offline":
            problems.append(f"{name} validate is paired with not_checkable_offline")
        if item.get("class") in {"critical", "high"} and disposition == "document":
            if "src/agentforge/agents/approval.py" not in action:
                problems.append(f"{name} document action does not name the human gate")
        if "decide()" in action and "do not call decide()" not in action.lower():
            problems.append(f"{name} next_action calls decide()")
    return problems


def main() -> int:
    problems = check(REPORT)
    if problems:
        print("\n".join(problems))
        return 1
    print(f"triage ok: {REPORT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
