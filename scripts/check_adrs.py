#!/usr/bin/env python3
"""ADR check. Exit 1 if an ADR lacks a status, a decision section or at least two rejected alternatives.

Counts headings that start with "### Rejected". Usage: check_adrs.py [repo_root]
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) > 1 else Path(__file__).resolve().parents[1]
    adr_dir = root / "Docs" / "adr"
    files = sorted(p for p in adr_dir.glob("[0-9][0-9][0-9]-*.md"))
    problems: list[str] = []
    if not files:
        problems.append("no ADRs found")
    index = (adr_dir / "README.md").read_text() if (adr_dir / "README.md").exists() else ""
    for f in files:
        text = f.read_text()
        rejected = len(re.findall(r"^### Rejected", text, re.M))
        if rejected < 2:
            problems.append(f"{f.name}: {rejected} rejected alternative(s), need at least 2")
        if not re.search(r"^- Status: ", text, re.M):
            problems.append(f"{f.name}: missing Status")
        if not re.search(r"^## Decision", text, re.M):
            problems.append(f"{f.name}: missing Decision section")
        if f.name not in index:
            problems.append(f"{f.name}: not listed in adr/README.md")
    for p in problems:
        print("ADR", p)
    print(f"adr check: {len(files)} ADR(s), {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
