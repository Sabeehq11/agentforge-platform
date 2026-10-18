#!/usr/bin/env python3
"""Schema-diff check. Exit 1 if a v1 schema changed in a breaking way without a version bump.

Breaking, and refused while the file stays under contracts/v1:
- a required field was removed
- a property type changed
- an enum or const lost a value

Adding an optional property is not breaking. It still needs a migration note; this script checks the schema, and the
note is recorded in Docs/DECISIONS.md section 5.

Comparison is against the committed copy (git show HEAD). A repository with no commits yet has nothing to compare,
so the check passes and says so. Tests pass an explicit baseline directory instead of git.
Usage: check_schema_diff.py [repo_root]
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any


def _load(text: str) -> dict[str, Any]:
    data: Any = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("schema is not an object")
    return data


def _properties(schema: dict[str, Any]) -> dict[str, Any]:
    props = schema.get("properties")
    return props if isinstance(props, dict) else {}


def breaking(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    """Differences that require a new contracts/vN directory. Empty when the change is compatible."""
    problems: list[str] = []
    old_required = set(old.get("required") or [])
    new_required = set(new.get("required") or [])
    for name in sorted(old_required - new_required):
        problems.append(f"required field removed: {name}")
    old_props, new_props = _properties(old), _properties(new)
    for name in sorted(set(old_props) & set(new_props)):
        before, after = old_props[name], new_props[name]
        if not isinstance(before, dict) or not isinstance(after, dict):
            continue
        if before.get("type") != after.get("type") and "type" in before:
            problems.append(f"type changed: {name}")
        if "enum" in before and set(before["enum"]) - set(after.get("enum") or []):
            problems.append(f"enum narrowed: {name}")
        if "const" in before and before["const"] != after.get("const"):
            problems.append(f"const changed: {name}")
    return problems


def _committed(root: Path) -> dict[str, str]:
    try:
        out = subprocess.run(
            ["git", "ls-tree", "-r", "--name-only", "HEAD", "contracts/v1"],
            cwd=root, capture_output=True, text=True, check=True,
        ).stdout
    except subprocess.CalledProcessError:
        return {}
    found: dict[str, str] = {}
    for rel in out.splitlines():
        text = subprocess.run(
            ["git", "show", f"HEAD:{rel}"], cwd=root, capture_output=True, text=True, check=True,
        ).stdout
        found[rel] = text
    return found


def compare(baseline: dict[str, dict[str, Any]], current: dict[str, dict[str, Any]]) -> list[str]:
    problems: list[str] = []
    for rel in sorted(set(baseline) & set(current)):
        for item in breaking(baseline[rel], current[rel]):
            problems.append(f"{rel}: {item}")
    return problems


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) > 1 else Path(__file__).resolve().parents[1]
    committed = _committed(root)
    if not committed:
        print("schema diff: no committed contracts/v1 to compare; nothing to check")
        return 0
    problems: list[str] = []
    for rel, text in sorted(committed.items()):
        path = root / rel
        if not path.is_file():
            problems.append(f"{rel}: removed from v1 without a version bump")
            continue
        for item in breaking(_load(text), _load(path.read_text(encoding="utf-8"))):
            problems.append(f"{rel}: {item}")
    for p in problems:
        print("BREAKING", p)
    print(f"schema diff: {len(committed)} schema(s), {len(problems)} breaking change(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
