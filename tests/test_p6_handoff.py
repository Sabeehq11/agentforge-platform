"""P6 version baseline and handoff. Records only: no attack, no replay, no regression_cases write."""

from __future__ import annotations

import sqlite3

from agentforge.orchestrator.policy import Weights
from agentforge.orchestrator.priority import load_evidence, next_category
from agentforge.orchestrator.versions import Observation, observe_version, pending_handoffs
from agentforge.store.records import insert_exploit
from tests.fixtures import PIN_A, PIN_B, PIN_C, ScriptedTransport, p6_campaign, p6_store

CID = "corr-p6"
SEEDED = frozenset({"TM-PI", "TM-EX", "TM-DS"})
ORDER = ("TM-PI", "TM-EX", "TM-DS")


def _count(conn: sqlite3.Connection, table: str) -> int:
    return int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])  # nosec B608


def _observe(conn: sqlite3.Connection, pin: str, verified: bool = True) -> Observation:
    return observe_version(conn, pin, identity_verified=verified, correlation_id=CID)


def _ranks(conn: sqlite3.Connection) -> dict[str, int]:
    return {s.category: s.total for s in next_category(conn, PIN_A, SEEDED, Weights(), ORDER).ordered}


def test_first_verified_pin_is_a_baseline_with_no_handoff_or_rank_change() -> None:
    conn = p6_store()
    before = _ranks(conn)
    assert _observe(conn, PIN_A).action == "baseline"
    assert (_count(conn, "version_baselines"), _count(conn, "version_handoffs")) == (1, 0)
    assert not load_evidence(conn, PIN_A).pending_handoff
    assert _ranks(conn) == before
    assert _observe(conn, PIN_A).action == "unchanged"
    assert (_count(conn, "version_baselines"), _count(conn, "version_handoffs")) == (1, 0)


def test_a_different_verified_pin_writes_exactly_one_pending_handoff() -> None:
    conn = p6_store()
    _observe(conn, PIN_A)
    result = _observe(conn, PIN_B)
    assert (result.action, result.previous_pin) == ("handoff", PIN_A)
    for _ in range(3):  # repeated, or killed and resumed midway: still one row
        assert _observe(conn, PIN_B).action == "unchanged"
    assert pending_handoffs(conn) == [(PIN_A, PIN_B)]


def test_a_third_pin_chains_to_the_second() -> None:
    conn = p6_store()
    for pin in (PIN_A, PIN_B, PIN_C):
        _observe(conn, pin)
    assert pending_handoffs(conn) == [(PIN_A, PIN_B), (PIN_B, PIN_C)]


def test_unverified_identity_or_malformed_pin_records_nothing() -> None:
    conn = p6_store()
    assert _observe(conn, PIN_A, verified=False).action == "refused"
    assert _count(conn, "version_baselines") == 0
    for bad in ("", "XYZ", "9F03654", "abc", "g" * 8, "a" * 41):
        assert _observe(conn, bad).action == "refused"
    assert (_count(conn, "version_baselines"), _count(conn, "version_handoffs")) == (0, 0)
    _observe(conn, PIN_A)
    assert _observe(conn, PIN_B, verified=False).action == "refused"
    assert _observe(conn, "nothex!").action == "refused"
    assert _count(conn, "version_handoffs") == 0


def test_a_pin_that_returns_reuses_its_row_and_logs_a_rollback_note() -> None:
    conn = p6_store()
    p6_campaign(conn)
    for pin in (PIN_A, PIN_B):
        _observe(conn, pin)
    assert _observe(conn, PIN_A).action == "rollback_observed"
    assert (_count(conn, "version_baselines"), _count(conn, "version_handoffs")) == (1, 1)
    note = conn.execute("SELECT note FROM campaigns WHERE correlation_id = ?", (CID,)).fetchone()[0]
    assert note == "rollback_observed"


def test_handoff_path_sends_nothing_and_writes_no_regression_or_exploit_rows() -> None:
    conn = p6_store()
    transport = ScriptedTransport()
    _observe(conn, PIN_A)
    _observe(conn, PIN_B)
    assert transport.calls == []
    assert (_count(conn, "regression_cases"), _count(conn, "exploits"), _count(conn, "dispatch_journal")) == (0, 0, 0)
    row = conn.execute("SELECT status, claimed_by FROM version_handoffs").fetchone()
    assert tuple(row) == ("pending", None)  # P7 claims it


def test_a_pending_handoff_alone_raises_no_category_and_evidence_scores_only_its_category() -> None:
    conn = p6_store()
    _observe(conn, PIN_A)
    _observe(conn, PIN_B)
    assert load_evidence(conn, PIN_A).pending_handoff
    assert _ranks(conn) == {"TM-DS": 40, "TM-EX": 40, "TM-PI": 40}  # coverage gaps only, no regression score
    insert_exploit(
        conn,
        {
            "id": "exp-1", "severity": "low", "category": "TM-PI", "reproduction_steps": "s",
            "observed_behavior": "o", "expected_behavior": "e", "system_version": PIN_A, "status": "draft",
        },
    )
    assert _ranks(conn) == {"TM-PI": 100, "TM-DS": 40, "TM-EX": 40}
