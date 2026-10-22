#!/usr/bin/env python3
"""Offline GO or NO-GO per gate for the R7-R8 operational steps. Reads local files only.

No network, no process, no secret, no environment variable, no `.env`, no database. It prints one line per gate and
exits non-zero if any gate is NO-GO, which is the expected result until the gated evidence exists. GO is a necessary
condition, not an approval: every operational gate still needs your explicit approval.
"""

from __future__ import annotations

import argparse
import sys
from datetime import date
from decimal import Decimal, InvalidOperation
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentforge.gates.preflight import r8_level, run_preflight  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline R7-R8 preflight. Never makes a request."
    )
    parser.add_argument("--root", default=str(ROOT), help="repo root to inspect")
    parser.add_argument(
        "--request-usd",
        default="0",
        help="reservation to test against the $12.00 lifetime ceiling",
    )
    args = parser.parse_args(argv)
    try:
        request = Decimal(args.request_usd)
    except InvalidOperation:
        print("refused: --request-usd is not a number", file=sys.stderr)
        return 2
    if not request.is_finite() or request < 0:
        print("refused: --request-usd must be a non-negative number", file=sys.stderr)
        return 2
    root = Path(args.root)
    today = date.today()
    results = run_preflight(root, today=today, request_usd=request)
    for item in results:
        print(f"{item.label:6} {item.name}: {item.reason}")
    print(
        f"R8 status: {r8_level(root, today)} (accepted only with valid evidence and the committed attestation)"
    )
    ok = all(item.go for item in results)
    print("PREFLIGHT: GO (necessary, not an approval)" if ok else "PREFLIGHT: NO-GO")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
