"""Documentation drafts: required fields, uniqueness, PHI, three reports, fix-validation."""

from __future__ import annotations

import sqlite3

import pytest

from agentforge.agents.documentation import draft_report
from agentforge.harness.stub_target import StubReply, StubTarget
from agentforge.harness.suite import claim_handoff, run_suite
from agentforge.safety.phi import PhiRefused
from agentforge.store.migrate import migrate
from agentforge.store.records import DuplicateSequence, StoreError, insert_exploit, insert_regression_case, sequence_hash
from tests.fixtures import confirmed_exploit


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys = ON")
    migrate(conn)
    return conn


def _exploit(conn: sqlite3.Connection, exploit: dict[str, object]) -> None:
    insert_exploit(
        conn,
        {
            "id": exploit["exploit_id"],
            "severity": exploit["severity"],
            "category": exploit["category"],
            "reproduction_steps": exploit["minimal_sequence"],
            "observed_behavior": exploit["observed_behavior"],
            "expected_behavior": exploit["expected_behavior"],
            "system_version": "aaaaaaa",
        },
    )


def test_a_draft_has_the_six_fields_and_a_second_draft_is_the_same_id() -> None:
    conn = _conn()
    exploit = confirmed_exploit()
    _exploit(conn, exploit)
    report_id = draft_report(conn, exploit)  # type: ignore[arg-type]
    body = conn.execute("SELECT body, status FROM reports WHERE id = ?", (report_id,)).fetchone()
    assert body[1] == "draft"
    for heading in ("Severity:", "Clinical impact:", "Minimal sequence:", "Observed:", "Expected:", "Remediation:", "Fix validation:"):
        assert heading in body[0]
    assert draft_report(conn, exploit) == report_id  # type: ignore[arg-type]


def test_a_duplicate_sequence_does_not_write_a_report() -> None:
    conn = _conn()
    exploit = confirmed_exploit()
    _exploit(conn, exploit)
    other = dict(exploit)
    other["exploit_id"] = "exp-2"
    with pytest.raises(DuplicateSequence):
        insert_exploit(
            conn,
            {
                "id": "exp-2",
                "severity": "high",
                "category": "TM-EX",
                "reproduction_steps": exploit["minimal_sequence"],
                "observed_behavior": "again",
                "expected_behavior": "refused",
                "system_version": "aaaaaaa",
            },
        )
    with pytest.raises(StoreError):
        draft_report(conn, other)  # type: ignore[arg-type]
    assert conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0] == 0


def test_phi_is_refused() -> None:
    conn = _conn()
    exploit = confirmed_exploit()
    exploit["observed_behavior"] = "patient email ada@example.com was quoted"
    _exploit(conn, exploit)
    with pytest.raises(PhiRefused):
        draft_report(conn, exploit)  # type: ignore[arg-type]
    assert conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0] == 0


def test_three_distinct_reports_and_fix_validation_cites_runs_without_publishing() -> None:
    conn = _conn()
    ids = []
    for index, category, subcategory in (("pi", "TM-PI", "TM-PI-1"), ("ex", "TM-EX", "TM-EX-3"), ("ds", "TM-DS", "TM-DS-1")):
        exploit = confirmed_exploit()
        exploit["exploit_id"] = f"exp-{index}"
        exploit["category"] = category
        exploit["minimal_sequence"] = {"channel": "chat", "turns": [{"role": "user", "content": f"sequence {index}"}]}
        _exploit(conn, exploit)
        ids.append(draft_report(conn, exploit))  # type: ignore[arg-type]
        insert_regression_case(
            conn,
            case_id=f"rc-exp-{index}",
            exploit_id=f"exp-{index}",
            category=category,
            subcategory=subcategory,
            invariant_id="canary" if subcategory != "TM-EX-3" else "missing_authority",
            expected_safe_behavior=str(exploit["expected_behavior"]),
            system_version="aaaaaaa",
        )
    assert len(set(ids)) == 3
    digest = sequence_hash({"channel": "chat", "turns": [{"role": "user", "content": "sequence pi"}]})
    conn.execute(
        "INSERT INTO version_baselines (target_pin, recorded_at, identity_checked_at, correlation_id) VALUES ('aaaaaaa', '2026-10-19T00:00:00Z', '2026-10-19T00:00:00Z', 'corr-1')"
    )
    conn.execute(
        "INSERT INTO version_handoffs (target_pin, previous_pin, detected_at, status, correlation_id) VALUES ('bbbbbbb', 'aaaaaaa', '2026-10-19T00:00:00Z', 'pending', 'corr-1')"
    )
    handoff = int(conn.execute("SELECT id FROM version_handoffs").fetchone()[0])
    claim_handoff(conn, handoff, "corr-1")
    replies = {
        sequence_hash({"channel": "chat", "turns": [{"role": "user", "content": f"sequence {name}"}]}): StubReply(200, "I will not follow that instruction.")
        for name in ("pi", "ds")
    }
    replies[sequence_hash({"channel": "chat", "turns": [{"role": "user", "content": "sequence ex"}]})] = StubReply(401, "")
    run_suite(conn, handoff, "corr-1", StubTarget(replies))
    row = conn.execute(
        "SELECT status, fix_validation, evidence_run_ids, body FROM reports WHERE exploit_id = 'exp-pi'"
    ).fetchone()
    assert row[0] == "draft"
    assert row[1] == "fixed"
    assert row[2]
    assert f"Fix validation: fixed; pin bbbbbbb; runs {row[2]}" in row[3]
    assert digest
