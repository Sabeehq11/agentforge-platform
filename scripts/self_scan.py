#!/usr/bin/env python3
"""Platform self-scan. Exit 1 if coverage, mypy, Bandit or pip-audit fails.

Each tool is a subprocess. This script does not call a model or the target, and it does not set LIVE_ENABLED.
The coverage floor stays 85. A higher floor is not invented here. Usage: self_scan.py [repo_root]
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def _run(root: Path, args: list[str]) -> int:
    print("+", " ".join(args), flush=True)
    completed = subprocess.run(args, cwd=root, check=False)
    return int(completed.returncode)


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) > 1 else Path(__file__).resolve().parents[1]
    steps = (
        [sys.executable, "-m", "pytest", "--cov=agentforge", "--cov-report=term-missing", "--cov-fail-under=85"],
        [sys.executable, "-m", "mypy", "src"],
        [sys.executable, "-m", "bandit", "-r", "src", "-ll", "-iii", "-q"],
        [sys.executable, "-m", "pip_audit"],
    )
    failed = 0
    for args in steps:
        code = _run(root, args)
        if code != 0:
            failed += 1
            print(f"self-scan failed: {' '.join(args[2:])} exited {code}", file=sys.stderr)
    print(f"self-scan: {len(steps)} step(s), {failed} failure(s)")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
