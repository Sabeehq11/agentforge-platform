#!/usr/bin/env python3
"""Threat-model check (P1). Exit 1 if the model is incomplete or something references an ID it does not define.

Rules:
1. THREAT_MODEL.md defines every subcategory ID (TM-XX-N) with all four attributes, and all six PRD categories.
2. Every TM- ID referenced anywhere else in the repo exists in the model. A reference scan with nothing to scan passes.
3. The summary is between 450 and 550 words (the PRD asks for about 500), and all 20 OWASP rows are present.

No network access. Usage: check_threat_model.py [repo_root]
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

SUMMARY_MIN, SUMMARY_MAX = 450, 550
REQUIRED_CATEGORIES = ("TM-PI", "TM-EX", "TM-SC", "TM-TM", "TM-DS", "TM-ID")
ATTRIBUTES = ("attack surface", "impact", "difficulty", "existing defenses")
WEB_ROWS = tuple(f"A{n:02d}" for n in range(1, 11))
LLM_ROWS = tuple(f"LLM{n:02d}" for n in range(1, 11))

HEADING = re.compile(r"^(#{2,4}) +(\S+)")
WORD = re.compile(r"[A-Za-z0-9']+")
REF = re.compile(r"TM-[A-Z]+-\d+")
FENCE = re.compile(r"^\s*(```|~~~)")
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", ".mypy_cache", ".ruff_cache", ".pytest_cache"}


def summary_words(text: str) -> int | None:
    """Words between the Summary heading and the next heading. None if there is no Summary section."""
    lines = text.splitlines()
    start = next((i for i, ln in enumerate(lines) if ln.startswith("## Summary")), None)
    if start is None:
        return None
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("#")), len(lines))
    return len(WORD.findall("\n".join(lines[start + 1:end])))


def sections(text: str) -> list[tuple[str, str]]:
    """(heading, body) for every heading, so an ID can be checked against its own section."""
    found: list[tuple[int, str]] = []
    for i, line in enumerate(text.splitlines()):
        m = HEADING.match(line)
        if m:
            found.append((i, m.group(2).rstrip(".")))
    out: list[tuple[str, str]] = []
    lines = text.splitlines()
    for n, (i, name) in enumerate(found):
        j = found[n + 1][0] if n + 1 < len(found) else len(lines)
        out.append((name, "\n".join(lines[i:j]).lower()))
    return out


def check_model(text: str) -> tuple[list[str], set[str]]:
    """Problems in the model itself, and the set of subcategory IDs it defines."""
    problems: list[str] = []
    words = summary_words(text)
    if words is None:
        problems.append("no Summary section")
    elif not SUMMARY_MIN <= words <= SUMMARY_MAX:
        problems.append(f"summary is {words} words, expected {SUMMARY_MIN}-{SUMMARY_MAX}")

    defined: set[str] = set()
    bodies: dict[str, str] = {}
    for name, body in sections(text):
        if REF.fullmatch(name):
            defined.add(name)
            bodies[name] = body
    for cat in REQUIRED_CATEGORIES:
        if not any(i.startswith(cat + "-") for i in defined):
            problems.append(f"missing PRD category {cat}")
    for i in sorted(defined):
        missing = [a for a in ATTRIBUTES if a not in bodies[i]]
        if missing:
            problems.append(f"{i}: missing attribute(s): {', '.join(missing)}")

    present = set(re.findall(r"\bA\d{2}\b|\bLLM\d{2}\b", text))
    for row in (*WEB_ROWS, *LLM_ROWS):
        if row not in present:
            problems.append(f"missing OWASP row {row}")
    return problems, defined


def referenced(root: Path) -> list[tuple[str, str]]:
    """(location, ID) for every TM- reference outside the threat model."""
    out: list[tuple[str, str]] = []
    for f in sorted(root.rglob("*")):
        if not f.is_file() or SKIP_DIRS & set(f.relative_to(root).parts):
            continue
        if f.name == "THREAT_MODEL.md" or f.suffix not in {".md", ".py", ".yaml", ".yml"}:
            continue
        try:
            lines = f.read_text(errors="ignore").splitlines()
        except OSError:
            continue
        fenced = False
        for n, line in enumerate(lines, 1):
            if FENCE.match(line):
                fenced = not fenced
            if fenced:
                continue
            for i in REF.findall(line):
                out.append((f"{f.relative_to(root)}:{n}", i))
    return out


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) > 1 else Path(__file__).resolve().parents[1]
    model = root / "THREAT_MODEL.md"
    problems: list[str] = []
    if not model.is_file():
        problems.append("THREAT_MODEL.md is missing")
        defined: set[str] = set()
    else:
        problems, defined = check_model(model.read_text())
    refs = referenced(root)
    for loc, i in refs:
        if i not in defined:
            problems.append(f"{loc}: references {i}, which is not in the threat model")
    for p in problems:
        print("THREAT", p)
    print(f"threat model check: {len(defined)} subcategory ID(s), {len(refs)} reference(s), {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
