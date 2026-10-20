#!/usr/bin/env python3
"""Write the offline 100-case baseline. No live path. Does not edit config/budget.yaml."""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentforge.observe.baseline import run_baseline  # noqa: E402
from agentforge.safety.chokepoint import LIVE_ENABLED  # noqa: E402


def main(argv: list[str]) -> int:
    if "--live" in argv or LIVE_ENABLED:
        print("refused: this script has no live path", file=sys.stderr)
        return 2
    out = ROOT / "evals" / "results" / "baseline-p8.json"
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys = ON")
    payload = run_baseline(conn)
    out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {out} cases={payload['cases']} campaigns={payload['attack_loop']['campaigns']} live={payload['live']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
