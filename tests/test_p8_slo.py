"""SLO times run_suite. Index EXPLAIN is a separate proof and is not the SLO."""

from __future__ import annotations

import sqlite3

from agentforge.observe.slo import OPERATION, load_slo, measure, seed_suite

QUERIES = {
    "idx_exploits_severity": "SELECT id, severity FROM exploits WHERE severity = 'medium'",
    "idx_exploits_category": "SELECT id, category FROM exploits WHERE category = 'TM-PI'",
    "idx_exploits_system_version": "SELECT id, system_version FROM exploits WHERE system_version = 'baseline1'",
}


def _seeded() -> tuple[sqlite3.Connection, int]:
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys = ON")
    return conn, seed_suite(conn, 100)


def test_slo_times_run_suite_and_counts_replays() -> None:
    conn, handoff_id = _seeded()
    result = measure(conn, handoff_id)
    assert result.operation == OPERATION
    assert result.timed_call == "run_suite"
    assert result.cases == 100
    assert result.replays == result.cases * 3
    assert result.passed is True
    assert result.elapsed_seconds <= load_slo().ceiling_seconds


def test_select_only_timer_does_not_pass() -> None:
    conn, handoff_id = _seeded()
    result = measure(conn, handoff_id, timed_call="select")
    assert result.timed_call == "select"
    assert result.replays == 0
    assert result.passed is False


def test_ceiling_below_elapsed_fails() -> None:
    conn, handoff_id = _seeded()
    result = measure(conn, handoff_id, ceiling_seconds=0.0)
    assert result.timed_call == "run_suite"
    assert result.elapsed_seconds > 0
    assert result.passed is False


def test_explain_names_an_index_and_is_not_the_slo() -> None:
    conn, _handoff = _seeded()
    for index, sql in QUERIES.items():
        plan = " ".join(str(row[3]) for row in conn.execute("EXPLAIN QUERY PLAN " + sql))
        assert index in plan
        assert "SCAN exploits" not in plan or index in plan
    assert "stub_regression_suite" not in " ".join(QUERIES)
