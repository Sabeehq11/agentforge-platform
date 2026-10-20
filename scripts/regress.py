#!/usr/bin/env python3
"""Dry-run the regression suite against the in-process stub. Never calls the live transport.

There is no --live flag. LIVE_ENABLED is not consulted and is not set. A missing handoff prints
nothing to replay and exits 0.
"""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentforge.harness.stub_target import StubTarget  # noqa: E402
from agentforge.harness.suite import claim_handoff, run_suite, suite_result_json  # noqa: E402
from agentforge.store.migrate import migrate  # noqa: E402


def main(argv: list[str]) -> int:
    if "--live" in argv:
        print("refused: this script has no live path", file=sys.stderr)
        return 2
    db = ROOT / "data" / "agentforge.db"
    if not db.exists():
        print("no store; nothing to replay")
        return 0
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA foreign_keys = ON")
    migrate(conn)
    row = conn.execute(
        "SELECT id, status, claimed_by FROM version_handoffs WHERE status IN ('pending', 'claimed') ORDER BY id LIMIT 1"
    ).fetchone()
    if row is None:
        print("no pending handoff")
        return 0
    handoff_id, status, owner = int(row[0]), str(row[1]), row[2]
    correlation_id = owner or "corr-dry-run"
    if status == "pending":
        if claim_handoff(conn, handoff_id, correlation_id) != "claimed":
            print("handoff was not claimed")
            return 1
    print(suite_result_json(run_suite(conn, handoff_id, str(correlation_id), StubTarget())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
