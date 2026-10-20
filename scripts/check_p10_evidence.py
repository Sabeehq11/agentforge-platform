#!/usr/bin/env python3
"""P10 evidence-file presence check. Exit 1 if a required file is missing or mislabeled.

Does not fetch, scan secrets, or run Bandit. Does not open a socket.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    "evals/triage/scan-report.json",
    "evals/results/drills-p10.json",
    "Docs/INTEGRATION_PACKET.md",
    "Docs/ATO_PACKET.md",
    "Docs/COST_ANALYSIS.md",
)
FIELDS = ("validation_evidence", "disposition", "rationale", "next_action")


def _pins(root: Path) -> set[str]:
    text = (root / "pyproject.toml").read_text(encoding="utf-8")
    runtime = []
    collecting = False
    for line in text.splitlines():
        if line.strip().startswith("dependencies"):
            collecting = True
            continue
        if collecting:
            if line.strip().startswith("]"):
                break
            spec = line.strip().strip('",')
            if "==" in spec:
                runtime.append(f"{spec} runtime")
    dev = []
    for raw in (root / "requirements-dev.txt").read_text(encoding="utf-8").splitlines():
        item = raw.strip()
        if item and not item.startswith("#"):
            dev.append(f"{item} dev")
    return set(["python>=3.12,<3.13 runtime", *runtime, *dev])


def check(root: Path) -> list[str]:
    problems: list[str] = []
    for rel in REQUIRED:
        path = root / rel
        if not path.is_file() or path.stat().st_size == 0:
            problems.append(f"missing or empty: {rel}")
    packet = root / "Docs" / "INTEGRATION_PACKET.md"
    if packet.is_file():
        first = packet.read_text(encoding="utf-8").splitlines()[0]
        if "peer integration" in first.lower() and "not peer integration" not in first.lower():
            problems.append("integration packet describes itself as peer integration")
        if "not peer integration" not in packet.read_text(encoding="utf-8").lower():
            problems.append("integration packet does not deny peer integration")
    drills = root / "evals" / "results" / "drills-p10.json"
    if drills.is_file():
        body = json.loads(drills.read_text(encoding="utf-8"))
        if body.get("live") is not False:
            problems.append("drills-p10.json live is not false")
    triage = root / "evals" / "triage" / "scan-report.json"
    if triage.is_file():
        findings = json.loads(triage.read_text(encoding="utf-8")).get("findings", [])
        for item in findings:
            for field in FIELDS:
                if field not in item:
                    problems.append(f"triage finding missing {field}")
    inventory = root / "Docs" / "ato" / "dependencies.txt"
    if inventory.is_file():
        listed = {line.strip() for line in inventory.read_text(encoding="utf-8").splitlines() if line.strip()}
        if listed != _pins(root):
            problems.append("dependency inventory does not match the committed pins")
    scan = root / "Docs" / "ato" / "self-scan.txt"
    if scan.is_file() and "date:" not in scan.read_text(encoding="utf-8"):
        problems.append("self-scan file has no date")
    costs = root / "Docs" / "cost" / "unit-costs.json"
    if costs.is_file():
        rows = json.loads(costs.read_text(encoding="utf-8")).get("rows", [])
        bases = {row.get("projection_basis") for row in rows}
        if not {"reservation", "inferred"}.issubset(bases):
            problems.append("unit costs do not keep a reservation assumption and an inferred charge apart")
        if any(row.get("provider_charge_usd") is not None and row.get("projection_basis") == "inferred" for row in rows):
            problems.append("an inferred row is also marked as a verified provider charge")
    return problems


def main() -> int:
    problems = check(ROOT)
    if problems:
        print("\n".join(problems))
        return 1
    print("p10 evidence ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
