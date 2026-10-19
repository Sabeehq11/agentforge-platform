#!/usr/bin/env python3
"""Architecture check (P5). Exit 1 if ARCHITECTURE.md is missing a required part.

Deliberately light. It checks structure, not truth:
1. A Summary section of 400 to 650 words that names all four agents.
2. At least one mermaid diagram.
3. Sections A to K, an AI-use disclosure, API limits, pagination and a deployment note.
4. Each of sections A to K labels its claims, with at least one Built or Planned marker.

No network access. Usage: check_architecture.py [repo_root]
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

SUMMARY_MIN, SUMMARY_MAX = 400, 650
AGENTS = ("Orchestrator", "Red Team", "Judge", "Documentation")
LETTERS = "ABCDEFGHIJK"
EXTRA_HEADINGS = ("AI-use disclosure", "API limits", "Pagination", "Deployment note")
WORD = re.compile(r"[A-Za-z0-9']+")
MARKER = re.compile(r"\*\*(Built|Planned)")


def split_sections(text: str) -> dict[str, str]:
    """Heading text (without the leading hashes) to the body that follows it, for level-2 headings."""
    found: dict[str, str] = {}
    current: str | None = None
    buf: list[str] = []
    fenced = False
    for line in text.splitlines():
        if line.startswith("```"):
            fenced = not fenced
        if not fenced and line.startswith("## "):
            if current is not None:
                found[current] = "\n".join(buf)
            current = line[3:].strip()
            buf = []
        elif current is not None:
            buf.append(line)
    if current is not None:
        found[current] = "\n".join(buf)
    return found


def check(text: str) -> list[str]:
    problems: list[str] = []
    sections = split_sections(text)

    summary = sections.get("Summary")
    if summary is None:
        problems.append("no Summary section")
    else:
        words = len(WORD.findall(summary))
        if not SUMMARY_MIN <= words <= SUMMARY_MAX:
            problems.append(f"summary is {words} words, expected {SUMMARY_MIN}-{SUMMARY_MAX}")
        for agent in AGENTS:
            if agent not in summary:
                problems.append(f"summary does not name the {agent} agent")

    if "```mermaid" not in text:
        problems.append("no mermaid diagram")

    for letter in LETTERS:
        name = next((h for h in sections if h.startswith(f"{letter}. ")), None)
        if name is None:
            problems.append(f"missing section {letter}")
        elif not MARKER.search(sections[name]):
            problems.append(f"section {letter} has no Built or Planned label")

    for heading in EXTRA_HEADINGS:
        if not any(h.lower().startswith(heading.lower()) for h in sections):
            problems.append(f"missing section: {heading}")
    return problems


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) > 1 else Path(__file__).resolve().parents[1]
    path = root / "ARCHITECTURE.md"
    if not path.is_file():
        print("FAIL ARCHITECTURE.md is missing")
        return 1
    problems = check(path.read_text(encoding="utf-8"))
    if problems:
        print("FAIL")
        for problem in problems:
            print(f"  {problem}")
        return 1
    print("OK ARCHITECTURE.md has the required parts")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
