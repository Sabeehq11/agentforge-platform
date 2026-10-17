#!/usr/bin/env python3
"""Case-sensitive internal link check for markdown files. Exit 1 on a broken relative link.

Checks [text](path) and [text](path#anchor) targets that point inside the repo. External (http, https, mailto) links are
not fetched, so CI makes no network call. Path existence is compared with exact case, because CI runs on Linux while
the author's filesystem may be case-insensitive. Anchors are checked against GitHub-style heading slugs.
Usage: check_links.py [repo_root]
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote

LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
FENCE = re.compile(r"^\s*(```|~~~)")
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", ".mypy_cache", ".ruff_cache", ".pytest_cache"}


def slug(heading: str) -> str:
    s = re.sub(r"[`*_]", "", heading.strip().lower())
    s = re.sub(r"[^\w\- ]", "", s)
    return s.replace(" ", "-")


def anchors(path: Path) -> set[str]:
    out: set[str] = set()
    fenced = False
    for line in path.read_text(errors="ignore").splitlines():
        if FENCE.match(line):
            fenced = not fenced
        elif not fenced and line.startswith("#"):
            out.add(slug(line.lstrip("#")))
    return out


def exact_exists(root: Path, target: Path) -> bool:
    """True only if every path component matches the real name with exact case."""
    try:
        rel = target.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    cur = root.resolve()
    for part in rel.parts:
        if part not in {p.name for p in cur.iterdir()}:
            return False
        cur = cur / part
    return True


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) > 1 else Path(__file__).resolve().parents[1]
    problems: list[str] = []
    count = 0
    for md in sorted(root.rglob("*.md")):
        if SKIP_DIRS & set(md.relative_to(root).parts):
            continue
        fenced = False
        for n, line in enumerate(md.read_text(errors="ignore").splitlines(), 1):
            if FENCE.match(line):
                fenced = not fenced
                continue
            if fenced:
                continue
            for m in LINK.finditer(line):
                url = unquote(m.group(1))
                if re.match(r"^[a-z][a-z0-9+.-]*:", url, re.I) or url.startswith("//"):
                    continue
                count += 1
                path_part, _, frag = url.partition("#")
                target = md if not path_part else (md.parent / path_part)
                if path_part and not exact_exists(root, target):
                    problems.append(f"{md.relative_to(root)}:{n}: missing target {url}")
                    continue
                if frag and target.is_file() and target.suffix == ".md" and frag.lower() not in anchors(target):
                    problems.append(f"{md.relative_to(root)}:{n}: missing anchor #{frag} in {path_part or md.name}")
    for p in problems:
        print("BROKEN", p)
    print(f"link check: {count} internal link(s), {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
