#!/usr/bin/env python3
"""Budgeted OpenRouter model probe. Makes no call unless PROVIDER_ENABLED is true.

Reads the key from OPENROUTER_API_KEY at call time, including a gitignored .env. Does not print the key,
write config/models.yaml, or replace the labeled baseline. A stopped run records the error class only.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentforge.agents.judge import RulesJudge, StubJudgeModel  # noqa: E402
from agentforge.agents.probe import apply_measured_models, run_probe  # noqa: E402
from agentforge.local_env import load_local_env  # noqa: E402
from agentforge.safety.budget import NotApproved, load_caps  # noqa: E402
from agentforge.safety.ledger import Ledger, load_shared_budget  # noqa: E402
from agentforge.safety.operator_approval import load_approvals  # noqa: E402
from agentforge.safety.spend_limits import load_attestations  # noqa: E402
from agentforge.store.migrate import migrate  # noqa: E402

_TOKEN_ENV = "AGENTFORGE_BUDGET_TOKEN"
_SECRET_ENV = "AGENTFORGE_BUDGET_SECRET"


def _rules_judge() -> RulesJudge:
    """The fixture rules Judge the baseline was measured with. Its own ledger is in memory and spends nothing."""
    from agentforge.safety.budget import Budget

    local = sqlite3.connect(":memory:")
    migrate(local)
    caps = load_caps(ROOT / "config" / "budget.yaml")
    local_budget = Budget(caps)
    local_budget.approve(os.environ[_TOKEN_ENV], os.environ[_SECRET_ENV])
    return RulesJudge(
        str(ROOT / "config" / "models.yaml"),
        Ledger(local, local_budget),
        stub=StubJudgeModel({"rec-near-miss": "partial"}),
        fixture_only=True,
        canaries={"TM-PI-1": "CANARY-AF-PI1", "TM-PI-2": "CANARY-AF-PI2", "TM-PI-3": "CANARY-AF-PI3"},
    )


def main() -> int:
    load_local_env(ROOT / ".env")
    token = os.environ.get(_TOKEN_ENV, "")
    secret = os.environ.get(_SECRET_ENV, "")
    if not token or not secret:
        print("refused: missing operator budget token or secret", file=sys.stderr)
        return 2
    try:
        ledger_path = ROOT / "data" / "agentforge.sqlite3"
        ledger_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(ledger_path)
        migrate(conn)
        budget = load_shared_budget(conn, load_caps(ROOT / "config" / "budget.yaml"), token, secret)
        ledger = Ledger(conn, budget)
        report = run_probe(
            budget,
            ROOT / "evals" / "judge" / "labeled",
            ROOT / "evals" / "judge" / "baseline.json",
            reserve_usd=0.01,
            attestations=load_attestations(ROOT / "config" / "spend_limits.yaml"),
            approvals=load_approvals(ROOT / "config" / "operator_approval.yaml"),
            today=date.today(),
            report_dir=ROOT / "evals" / "results",
            ledger=ledger,
            judge=_rules_judge(),
        )
        if report["status"] == "measured":
            apply_measured_models(report, ROOT / "evals" / "judge" / "probe" / "candidates.json", ROOT / "config" / "models.yaml")
    except NotApproved as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    text = json.dumps(report)
    if os.environ.get("OPENROUTER_API_KEY", "") and os.environ["OPENROUTER_API_KEY"] in text:
        print("refused: probe output contained the key", file=sys.stderr)
        return 2
    print(text)
    return 0 if report["status"] == "measured" else 1


if __name__ == "__main__":
    raise SystemExit(main())
