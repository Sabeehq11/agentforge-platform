#!/usr/bin/env python3
"""Write Docs/ato/dependencies.txt from the committed pins. No network resolve."""

from __future__ import annotations

import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.12 is required
    import tomli as tomllib  # type: ignore[no-redef]


def pins(root: Path) -> list[str]:
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    lines = ["python>=3.12,<3.13 runtime"]
    for spec in project["project"]["dependencies"]:
        lines.append(f"{spec} runtime")
    for raw in (root / "requirements-dev.txt").read_text(encoding="utf-8").splitlines():
        text = raw.strip()
        if not text or text.startswith("#"):
            continue
        lines.append(f"{text} dev")
    return lines


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    path = root / "Docs" / "ato" / "dependencies.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(pins(root)) + "\n", encoding="utf-8")
    print(path.relative_to(root))
    return 0


if __name__ == "__main__":
    sys.exit(main())
