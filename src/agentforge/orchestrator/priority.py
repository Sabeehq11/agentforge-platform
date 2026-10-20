"""Category ranking from persisted evidence only. rank() is pure. Nothing is read from agent claims or memory.

Sources, loaded in one read transaction: coverage_metrics for the current system version, open high or critical rows
in exploits, regression_cases, signals and campaigns history. Weights come from config/orchestrator.yaml.

The regression component needs both a pending version handoff and persisted category evidence (a regression_cases
row or an exploits row in that category). A handoff carries no category, so it never raises a category alone.
When every score is 0 the fallback is the least-recently-run attackable category, then a fixed order.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field

from agentforge.orchestrator.policy import Weights

OPEN_SEVERITIES = ("critical", "high")
OPEN_STATUSES = ("draft", "pending_approval", "published")


@dataclass(frozen=True)
class Evidence:
    """A snapshot of persisted rows. Built by load_evidence and never by an agent."""

    coverage: dict[str, tuple[int, int, int]] = field(default_factory=dict)  # category -> case, pass, fail
    open_findings: frozenset[str] = frozenset()
    regression_evidence: frozenset[str] = frozenset()
    signals: dict[str, int] = field(default_factory=dict)
    last_run: dict[str, str] = field(default_factory=dict)  # category -> latest campaign update, ISO
    pending_handoff: bool = False


@dataclass(frozen=True)
class Score:
    category: str
    total: int
    components: dict[str, int]


@dataclass(frozen=True)
class Ranking:
    ordered: tuple[Score, ...]
    skipped: dict[str, str]
    fallback: bool
    note: str

    @property
    def first(self) -> str | None:
        return self.ordered[0].category if self.ordered else None

    def as_audit(self) -> dict[str, object]:
        return {
            "ordered": [{"category": s.category, "total": s.total, **s.components} for s in self.ordered],
            "skipped": dict(self.skipped),
            "fallback": self.fallback,
            "note": self.note,
        }


def load_evidence(conn: sqlite3.Connection, system_version: str) -> Evidence:
    """One read transaction, so the ranking is repeatable. Writes nothing."""
    began = not conn.in_transaction
    if began:
        conn.execute("BEGIN")
    try:
        coverage = {
            str(r[0]): (int(r[1]), int(r[2]), int(r[3]))
            for r in conn.execute(
                "SELECT category, case_count, pass_count, fail_count FROM coverage_metrics WHERE system_version = ?",
                (system_version,),
            )
        }
        marks = ",".join("?" for _ in OPEN_SEVERITIES)
        status_marks = ",".join("?" for _ in OPEN_STATUSES)
        open_findings = frozenset(
            str(r[0])
            for r in conn.execute(
                f"SELECT DISTINCT category FROM exploits WHERE severity IN ({marks}) AND status IN ({status_marks})",  # nosec B608
                (*OPEN_SEVERITIES, *OPEN_STATUSES),
            )
        )
        regression = frozenset(str(r[0]) for r in conn.execute("SELECT DISTINCT category FROM regression_cases"))
        confirmed = frozenset(
            str(r[0]) for r in conn.execute("SELECT DISTINCT category FROM exploits WHERE status != 'rejected'")
        )
        signals = {str(r[0]): int(r[1]) for r in conn.execute("SELECT category, COUNT(*) FROM signals GROUP BY category")}
        last_run: dict[str, str] = {}
        for raw, updated in conn.execute("SELECT request_json, updated_at FROM campaigns"):
            try:
                category = str(json.loads(raw)["category"])
            except (ValueError, KeyError, TypeError):
                continue
            if updated > last_run.get(category, ""):
                last_run[category] = str(updated)
        pending = conn.execute("SELECT 1 FROM version_handoffs WHERE status = 'pending' LIMIT 1").fetchone() is not None
    finally:
        if began:
            conn.rollback()
    return Evidence(coverage, open_findings, regression | confirmed, signals, last_run, pending)


def rank(
    evidence: Evidence,
    attackable: frozenset[str],
    weights: Weights,
    fallback_order: tuple[str, ...],
    *,
    categories: tuple[str, ...] = ("TM-PI", "TM-EX", "TM-SC", "TM-TM", "TM-DS", "TM-ID"),
) -> Ranking:
    """Order attackable categories by weighted persisted evidence. Ties break by category name.

    A category with no seed is skipped with a reason. Returns an empty ordering when nothing is attackable.
    """
    skipped = {c: "no seed for this category" for c in categories if c not in attackable}
    scores: list[Score] = []
    for category in sorted(c for c in categories if c in attackable):
        parts: dict[str, int] = {}
        if category in evidence.open_findings:
            parts["open_high_finding"] = weights.open_high_finding
        if evidence.pending_handoff and category in evidence.regression_evidence:
            parts["regression_component"] = weights.regression_component
        row = evidence.coverage.get(category)
        if row is None or row[0] == 0:
            parts["coverage_gap"] = weights.coverage_gap
        elif row[1] / row[0] < weights.low_pass_rate_below:
            parts["low_pass_rate"] = weights.low_pass_rate
        scores.append(Score(category, sum(parts.values()), parts))
    if not scores:
        return Ranking((), skipped, True, "nothing attackable")
    if any(s.total > 0 for s in scores):
        ordered = sorted(scores, key=lambda s: (-s.total, s.category))
        return Ranking(tuple(ordered), skipped, False, "weighted persisted evidence")
    # No-priority fallback: never-run first, then oldest run, then the fixed order, then the name.
    position = {c: i for i, c in enumerate(fallback_order)}
    ordered = sorted(
        scores,
        key=lambda s: (evidence.last_run.get(s.category, ""), position.get(s.category, len(position)), s.category),
    )
    return Ranking(tuple(ordered), skipped, True, "no priority: least recently run")


def next_category(
    conn: sqlite3.Connection,
    system_version: str,
    attackable: frozenset[str],
    weights: Weights,
    fallback_order: tuple[str, ...],
    *,
    exclude: frozenset[str] = frozenset(),
) -> Ranking:
    """Load the evidence once, then rank. exclude drops categories already tried in this campaign."""
    evidence = load_evidence(conn, system_version)
    return rank(evidence, attackable - exclude, weights, fallback_order)
