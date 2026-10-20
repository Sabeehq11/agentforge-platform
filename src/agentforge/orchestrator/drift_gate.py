"""Offline Judge drift gate for a variant campaign. Reuses the existing Judge and metrics, adds no grader.

The labeled set in evals/judge/labeled is scored through RulesJudge in stub and fixture-only mode and compared
with evals/judge/baseline.json by judge_metrics. It uses its own in-memory ledger with no reservation, so it touches
neither the shared ledger nor the provider, and it never edits the baseline. evals/results/judge-drift.json (the
provider probe output) is not read here.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from agentforge.agents.judge import RulesJudge, StubJudgeModel
from agentforge.agents.judge_metrics import LabelRejected, assert_no_drift, load_baseline, load_labeled, score
from agentforge.safety.budget import Budget, Caps, approval_token
from agentforge.safety.ledger import Ledger
from agentforge.store.migrate import migrate

ROOT = Path(__file__).resolve().parents[3]
LABELED = ROOT / "evals" / "judge" / "labeled"
BASELINE = ROOT / "evals" / "judge" / "baseline.json"
MODELS = ROOT / "config" / "models.yaml"
CANARIES = {"TM-PI-1": "CANARY-AF-PI1", "TM-PI-2": "CANARY-AF-PI2", "TM-PI-3": "CANARY-AF-PI3"}
_SECRET = "drift-gate-in-memory-not-a-credential"


class JudgeDrift(Exception):
    """The Judge fell below its committed baseline. The campaign is refused and nothing is sent."""


def _scratch_ledger() -> Ledger:
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys = ON")
    migrate(conn)
    caps = Caps(1.0, 1.0, 1, 5.0, 5.0)
    budget = Budget(caps)
    budget.approve(approval_token(caps, _SECRET), _SECRET)
    return Ledger(conn, budget)


def _prediction(outcome: dict[str, Any]) -> str:
    if "error_code" in outcome:
        raise LabelRejected("an error envelope is not a confirmed fail")
    if outcome.get("status") == "draft" and "verdict" not in outcome:
        return "fail"
    predicted = outcome.get("verdict")
    if predicted not in ("pass", "fail", "partial"):
        raise LabelRejected("verdict is not pass, fail, or partial")
    return str(predicted)


def check_judge_drift(*, labeled: Path = LABELED, baseline: Path = BASELINE, models: Path = MODELS) -> None:
    """Raise JudgeDrift when current rates fall below the baseline. Sends nothing and spends nothing."""
    judge = RulesJudge(
        str(models), _scratch_ledger(), stub=StubJudgeModel({"rec-near-miss": "partial"}), canaries=CANARIES,
        fixture_only=True,
    )
    pairs: list[tuple[str, str]] = []
    try:
        for item in load_labeled(labeled):
            raw = item["transcript"]
            sub = "TM-PI-1" if item.get("canary") else "TM-SC-1"
            result: Any = {
                "message_id": "drift", "correlation_id": raw["correlation_id"], "schema_version": "v1",
                "produced_at": "2026-10-19T00:00:00Z", "category": sub.rsplit("-", 1)[0], "subcategory": sub,
                "input_sequence": {"channel": "chat", "turns": [{"role": "user", "content": "drift check"}]},
                "expected_safe_behavior": "n/a", "observed_behavior": "pass", "severity": "low",
                "exploitability": "low", "regression_flag": False,
            }
            pairs.append((item["label"], _prediction(dict(judge.judge_transcript(result, raw)))))
        assert_no_drift(score(tuple(pairs)), load_baseline(baseline))
    except LabelRejected as exc:
        raise JudgeDrift(str(exc)) from exc
