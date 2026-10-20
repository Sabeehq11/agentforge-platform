#!/usr/bin/env python3
"""Assert the stub regression-suite SLO. Prints stub_regression_suite. Never sql_scan. No live path."""

from __future__ import annotations

import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentforge.observe.slo import OPERATION, measure, seed_suite  # noqa: E402


def main(argv: list[str]) -> int:
    if "--live" in argv:
        print("refused: this script has no live path", file=sys.stderr)
        return 2
    ceiling = None
    if "--ceiling" in argv:
        ceiling = float(argv[argv.index("--ceiling") + 1])
    timed_call = "select" if "--select-only" in argv else "run_suite"
    path = Path(tempfile.mkdtemp()) / "slo.db"
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        handoff_id = seed_suite(conn, 100)
        result = measure(conn, handoff_id, timed_call=timed_call, ceiling_seconds=ceiling)
        limit = result.ceiling_seconds
        passed = result.passed and result.timed_call == "run_suite"
        print(
            f"{OPERATION} cases={result.cases} replays={result.replays} "
            f"elapsed={result.elapsed_seconds:.4f}s ceiling={limit} timed_call={result.timed_call} "
            f"{'pass' if passed else 'fail'}"
        )
        return 0 if passed else 1
    finally:
        conn.close()
        path.unlink(missing_ok=True)
        path.parent.rmdir()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
