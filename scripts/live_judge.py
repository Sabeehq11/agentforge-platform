#!/usr/bin/env python3
"""Score one ambiguous labeled item with the provider Judge. Makes no call unless PROVIDER_ENABLED is true."""

from __future__ import annotations

import os
import sqlite3
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentforge.agents.probe import score_provider_judge  # noqa: E402
from agentforge.local_env import load_local_env  # noqa: E402
from agentforge.safety.budget import NotApproved, load_caps  # noqa: E402
from agentforge.safety.ledger import Ledger, load_shared_budget  # noqa: E402
from agentforge.safety.operator_approval import load_approvals  # noqa: E402
from agentforge.safety.spend_limits import load_attestations  # noqa: E402
from agentforge.store.migrate import migrate  # noqa: E402


def main() -> int:
    load_local_env(ROOT / ".env")
    token = os.environ.get("AGENTFORGE_BUDGET_TOKEN", "")
    secret = os.environ.get("AGENTFORGE_BUDGET_SECRET", "")
    if not token or not secret:
        print("refused: missing operator budget token or secret", file=sys.stderr)
        return 2
    try:
        path = ROOT / "data" / "agentforge.sqlite3"
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(path)
        migrate(conn)
        budget = load_shared_budget(conn, load_caps(ROOT / "config" / "budget.yaml"), token, secret)
        report = score_provider_judge(
            budget,
            ROOT / "evals" / "judge" / "labeled",
            model="anthropic/claude-sonnet-4.5",
            reserve_usd=0.01,
            attestations=load_attestations(ROOT / "config" / "spend_limits.yaml"),
            approvals=load_approvals(ROOT / "config" / "operator_approval.yaml"),
            today=date.today(),
            report_dir=ROOT / "evals" / "results",
            ledger=Ledger(conn, budget),
        )
    except NotApproved as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    print(report.get("status"))
    return 0 if report.get("status") == "measured" else 1


if __name__ == "__main__":
    raise SystemExit(main())
