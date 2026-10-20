#!/usr/bin/env python3
"""Print the six observability answers. Read only. No network, no provider, no live path."""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentforge.observe.queries import answers  # noqa: E402
from agentforge.store.migrate import migrate  # noqa: E402


def main(argv: list[str]) -> int:
    if "--live" in argv:
        print("refused: this script has no live path", file=sys.stderr)
        return 2
    db = ROOT / "data" / "agentforge.db"
    conn = sqlite3.connect(":memory:" if not db.exists() else db)
    conn.execute("PRAGMA foreign_keys = ON")
    migrate(conn)
    correlation_id = argv[1] if len(argv) > 1 and not argv[1].startswith("-") else None
    print(json.dumps(answers(conn, correlation_id), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
