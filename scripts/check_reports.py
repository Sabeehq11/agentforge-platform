#!/usr/bin/env python3
"""Report-format check. Exit 1 if a committed draft is missing a required heading or looks published.

No network. Does not read the store. Scans reports/*.md only.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

HEADINGS = (
    "Report:",
    "Severity:",
    "Category:",
    "Clinical impact:",
    "Minimal sequence:",
    "Observed:",
    "Expected:",
    "Remediation:",
    "Publication status:",
    "Remediation status:",
    "Fix validation:",
)
SECRET = re.compile(r"sk-or-v1-|BEGIN PRIVATE KEY|COPILOT_FIXTURE_PASSWORD")


def check(root: Path) -> list[str]:
    problems: list[str] = []
    files = sorted((root / "reports").glob("*.md"))
    ids: list[str] = []
    if len(files) < 3:
        problems.append(f"expected at least 3 reports, found {len(files)}")
    for path in files:
        text = path.read_text(encoding="utf-8")
        for heading in HEADINGS:
            if heading not in text:
                problems.append(f"{path.name} missing {heading}")
        if "Publication status: published" in text:
            problems.append(f"{path.name} is published")
        if "Live target: no" not in text:
            problems.append(f"{path.name} claims a live finding or omits the fixture line")
        if SECRET.search(text):
            problems.append(f"{path.name} matches a secret pattern")
        report_id = next((line.split(":", 1)[1].strip() for line in text.splitlines() if line.startswith("Report:")), "")
        ids.append(report_id)
    if len(ids) != len(set(ids)):
        problems.append("report ids are not unique")
    return problems


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) > 1 else Path(__file__).resolve().parents[1]
    problems = check(root)
    for item in problems:
        print(item, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
