"""Handoff and job share one transaction. A scheduled workflow is not this queue."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from agentforge.harness.stub_target import StubReply, StubTarget
from agentforge.harness.suite import SuiteKill, claim_handoff, job_depth, run_suite
from agentforge.orchestrator.versions import observe_version
from agentforge.store.access import grant_for_test
from agentforge.store.migrate import migrate
from agentforge.store.records import insert_exploit, insert_regression_case, sequence_hash

ROOT = Path(__file__).resolve().parents[1]
PIN_A = "aaaaaaa"
PIN_B = "bbbbbbb"
PIN_C = "ccccccc"
PIN_D = "ddddddd"


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys = ON")
    migrate(conn)
    from tests.fixtures import p6_campaign

    p6_campaign(conn, "corr-1")
    return conn


def _case(conn: sqlite3.Connection) -> str:
    insert_exploit(
        conn,
        {
            "id": "exp-1",
            "severity": "high",
            "category": "TM-PI",
            "reproduction_steps": "ask",
            "observed_behavior": "refused",
            "expected_behavior": "refuse",
            "system_version": PIN_A,
        },
        grant_for_test("judge"),
    )
    return insert_regression_case(
        conn,
        grant=grant_for_test("harness"),
        case_id="rc-1",
        exploit_id="exp-1",
        category="TM-PI",
        subcategory="TM-PI-1",
        invariant_id="canary",
        expected_safe_behavior="refuse",
        system_version=PIN_A,
    )


def test_a_repeated_observation_inserts_one_job() -> None:
    conn = _conn()
    assert observe_version(conn, PIN_A, identity_verified=True, correlation_id="corr-1").action == "baseline"
    assert observe_version(conn, PIN_B, identity_verified=True, correlation_id="corr-1").action == "handoff"
    assert observe_version(conn, PIN_B, identity_verified=True, correlation_id="corr-1").action == "unchanged"
    assert conn.execute("SELECT COUNT(*) FROM regression_jobs").fetchone()[0] == 1
    assert job_depth(conn) == 1


def test_a_raise_inside_the_handoff_transaction_leaves_neither_row() -> None:
    conn = _conn()
    observe_version(conn, PIN_A, identity_verified=True, correlation_id="corr-1")
    before_handoffs = conn.execute("SELECT COUNT(*) FROM version_handoffs").fetchone()[0]
    before_jobs = conn.execute("SELECT COUNT(*) FROM regression_jobs").fetchone()[0]
    try:
        with conn:
            conn.execute(
                "INSERT INTO version_handoffs (target_pin, previous_pin, detected_at, status, correlation_id) VALUES (?, ?, ?, 'pending', ?)",
                (PIN_B, PIN_A, "2026-10-20T00:00:02Z", "corr-1"),
            )
            raise sqlite3.OperationalError("injected before the job row")
    except sqlite3.OperationalError:
        pass
    assert conn.execute("SELECT COUNT(*) FROM version_handoffs").fetchone()[0] == before_handoffs
    assert conn.execute("SELECT COUNT(*) FROM regression_jobs").fetchone()[0] == before_jobs


def test_depth_three_claims_only_the_oldest() -> None:
    conn = _conn()
    observe_version(conn, PIN_A, identity_verified=True, correlation_id="corr-1")
    for pin in (PIN_B, PIN_C, PIN_D):
        observe_version(conn, pin, identity_verified=True, correlation_id="corr-1")
    assert job_depth(conn) == 3
    oldest = conn.execute("SELECT id FROM version_handoffs ORDER BY id LIMIT 1").fetchone()[0]
    assert claim_handoff(conn, int(oldest), "corr-1") == "claimed"
    pending = conn.execute("SELECT COUNT(*) FROM regression_jobs WHERE status = 'pending'").fetchone()[0]
    assert pending == 2
    later = conn.execute(
        "SELECT id FROM version_handoffs WHERE status = 'pending' ORDER BY id LIMIT 1"
    ).fetchone()[0]
    assert claim_handoff(conn, int(later), "corr-2") == "not_owner"


def test_a_kill_after_a_committed_repeat_is_not_replayed() -> None:
    conn = _conn()
    _case(conn)
    observe_version(conn, PIN_A, identity_verified=True, correlation_id="corr-1")
    observe_version(conn, PIN_B, identity_verified=True, correlation_id="corr-1")
    handoff = int(conn.execute("SELECT id FROM version_handoffs").fetchone()[0])
    assert claim_handoff(conn, handoff, "corr-1") == "claimed"
    digest = sequence_hash("ask")
    stub = StubTarget({digest: StubReply(200, "I will not follow that instruction.")})
    with pytest.raises(SuiteKill):
        run_suite(conn, handoff, "corr-1", stub, kill_after_calls=1)
    assert conn.execute("SELECT COUNT(*) FROM regression_runs").fetchone()[0] == 1
    assert conn.execute("SELECT status FROM regression_jobs").fetchone()[0] == "claimed"
    run_suite(conn, handoff, "corr-1", stub)
    assert conn.execute("SELECT COUNT(*) FROM regression_runs").fetchone()[0] == 3
    assert conn.execute("SELECT status FROM regression_jobs").fetchone()[0] == "done"


def test_schedule_workflow_does_not_open_the_local_store() -> None:
    text = (ROOT / ".github" / "workflows" / "regression-schedule.yml").read_text(encoding="utf-8")
    assert "agentforge.db" not in text
    assert "${{ secrets." not in text
    assert "LIVE_ENABLED" not in text
    assert "contents: read" in text
