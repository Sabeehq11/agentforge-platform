#!/usr/bin/env python3
"""Point this clone at scripts/hooks. Nothing is installed automatically. CI stays the enforced gate."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    subprocess.run(["git", "config", "core.hooksPath", "scripts/hooks"], cwd=ROOT, check=True)
    print("core.hooksPath set to scripts/hooks. The pre-commit hook runs scripts/secret_scan.py.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
