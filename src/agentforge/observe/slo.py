"""Time one stub regression-suite execution. Not a SQL timer and not a live scan.

The clock starts at the run_suite call and stops when it returns. Seeding, process startup and
EXPLAIN QUERY PLAN are outside the clock. The operation name is stub_regression_suite.
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

import yaml

from agentforge.harness.stub_target import StubTarget
from agentforge.harness.suite import claim_handoff, run_suite
from agentforge.store.migrate import migrate
from agentforge.store.records import insert_exploit, insert_regression_case

CONFIG = Path(__file__).resolve().parents[3] / "config" / "slo.yaml"
OPERATION = "stub_regression_suite"
REPEATS = 3
BASELINE_PIN = "baseline1"
TARGET_PIN = "target01"


@dataclass(frozen=True)
class SloConfig:
    operation: str
    cases: int
    repeats: int
    ceiling_seconds: float


@dataclass(frozen=True)
class SloResult:
    operation: str
    cases: int
    replays: int
    elapsed_seconds: float
    ceiling_seconds: float
    passed: bool
    timed_call: str


def load_slo(path: Path = CONFIG) -> SloConfig:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("slo.yaml must be a mapping")
    operation = str(raw["operation"])
    if operation != OPERATION:
        raise ValueError(f"slo operation must be {OPERATION}")
    cases = int(raw["cases"])
    repeats = int(raw["repeats"])
    ceiling = float(raw["ceiling_seconds"])
    if cases < 100 or repeats != REPEATS or ceiling <= 0:
        raise ValueError("slo.yaml needs at least 100 cases, 3 repeats and a positive ceiling")
    return SloConfig(operation, cases, repeats, ceiling)


def seed_suite(conn: sqlite3.Connection, cases: int) -> int:
    """Insert exploits, regression cases and a claimed handoff. Not part of the timed call."""
    migrate(conn)
    conn.execute(
        """
        INSERT INTO version_baselines (target_pin, recorded_at, identity_checked_at, correlation_id)
        VALUES (?, '2026-10-20T00:00:00Z', '2026-10-20T00:00:00Z', 'corr-slo')
        """,
        (BASELINE_PIN,),
    )
    for index in range(cases):
        exploit_id = f"slo-{index:04d}"
        steps = f"synthetic turn {index}"
        insert_exploit(
            conn,
            {
                "id": exploit_id,
                "severity": "medium",
                "category": "TM-PI",
                "reproduction_steps": steps,
                "observed_behavior": "refused",
                "expected_behavior": "refuse",
                "system_version": BASELINE_PIN,
            },
        )
        insert_regression_case(
            conn,
            case_id=f"case-{index:04d}",
            exploit_id=exploit_id,
            category="TM-PI",
            subcategory="TM-PI-1",
            invariant_id="canary",
            expected_safe_behavior="refuse",
            system_version=BASELINE_PIN,
        )
        # A completed suite on the predecessor pin, so the handoff is valid. These rows are not the timed scan.
        for repeat in range(1, REPEATS + 1):
            conn.execute(
                """
                INSERT INTO regression_runs (
                    case_id, system_version, correlation_id, repeat_index, outcome, invariant_id,
                    http_status, evidence_json, recorded_at
                ) VALUES (?, ?, 'corr-slo', ?, 'pass', 'canary', 200, '{}', '2026-10-20T00:00:00Z')
                """,
                (f"case-{index:04d}", BASELINE_PIN, repeat),
            )
    conn.execute(
        """
        INSERT INTO version_handoffs (target_pin, previous_pin, detected_at, status, correlation_id)
        VALUES (?, ?, '2026-10-20T00:00:01Z', 'pending', 'corr-slo')
        """,
        (TARGET_PIN, BASELINE_PIN),
    )
    conn.commit()
    handoff_id = int(conn.execute("SELECT id FROM version_handoffs WHERE target_pin = ?", (TARGET_PIN,)).fetchone()[0])
    claim_handoff(conn, handoff_id, "corr-slo")
    return handoff_id


def measure(
    conn: sqlite3.Connection,
    handoff_id: int,
    *,
    timed_call: str = "run_suite",
    ceiling_seconds: float | None = None,
) -> SloResult:
    """Time the named call. A SELECT-only timer is recorded and cannot pass."""
    config = load_slo()
    stub = StubTarget()
    started = time.perf_counter()
    if timed_call == "run_suite":
        result = run_suite(conn, handoff_id, "corr-slo", stub)
        cases = result.cases
    elif timed_call == "select":
        rows = conn.execute("SELECT id FROM regression_cases").fetchall()
        cases = len(rows)
        stub.calls.clear()
        replays = 0
    else:
        raise ValueError(f"unknown timed call {timed_call}")
    elapsed = time.perf_counter() - started
    replays = 0 if timed_call == "select" else len(stub.calls)
    ceiling = config.ceiling_seconds if ceiling_seconds is None else ceiling_seconds
    honest = timed_call == "run_suite" and replays == cases * config.repeats and cases >= config.cases
    return SloResult(
        operation=OPERATION,
        cases=cases,
        replays=replays,
        elapsed_seconds=elapsed,
        ceiling_seconds=ceiling,
        passed=honest and elapsed <= ceiling,
        timed_call=timed_call,
    )
