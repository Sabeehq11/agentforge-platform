"""Reconstruction names gaps. It does not invent rows, and it does not carry PHI."""

from __future__ import annotations

import json
import sqlite3
from datetime import date
from pathlib import Path

import pytest

from agentforge.agents.approval import decide, load_gate_approvals, submit_for_approval
from agentforge.agents.documentation import draft_report
from agentforge.orchestrator.state import log_run
from agentforge.orchestrator.trace import reconstruct
from agentforge.orchestrator.versions import observe_version
from agentforge.safety.phi import PhiRefused
from agentforge.store.access import issue_grant
from agentforge.store.migrate import migrate
from agentforge.store.records import insert_exploit
from tests.fixtures import confirmed_exploit, p6_campaign


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys = ON")
    migrate(conn)
    return conn


def test_a_complete_stub_run_reconstructs_in_order(tmp_path: Path) -> None:
    conn = _conn()
    p6_campaign(conn, "corr-1")
    log_run(conn, "corr-1", "orchestrator", "done")
    exploit = confirmed_exploit()
    exploit["correlation_id"] = "corr-1"
    insert_exploit(
        conn,
        {
            "id": exploit["exploit_id"],
            "severity": "high",
            "category": "TM-EX",
            "reproduction_steps": exploit["minimal_sequence"],
            "observed_behavior": exploit["observed_behavior"],
            "expected_behavior": exploit["expected_behavior"],
            "system_version": "aaaaaaa",
        },
        issue_grant("judge"),
    )
    report_id = draft_report(conn, exploit, issue_grant("documentation"))  # type: ignore[arg-type]
    submit_for_approval(conn, report_id)
    path = tmp_path / "approval.yaml"
    path.write_text(
        f"""approvals:
  - approved_by: operator-label
    approved_on: 2026-10-19
    purpose: publish_finding
    report_id: {report_id}
    bound: high
""",
        encoding="utf-8",
    )
    decide(conn, report_id, "published", load_gate_approvals(path), today=date(2026, 10, 19))
    conn.execute("UPDATE campaigns SET phase = 'done' WHERE correlation_id = 'corr-1'")
    view = reconstruct(conn, "corr-1")
    assert view["status"] == "complete"
    assert view["gaps"] == []
    encoded = json.dumps(view)
    assert "reproduction_steps" not in encoded
    assert "password" not in encoded
    assert "transcript" not in encoded


def test_deleting_the_approval_row_is_incomplete() -> None:
    conn = _conn()
    p6_campaign(conn, "corr-1")
    log_run(conn, "corr-1", "orchestrator", "done")
    log_run(conn, "corr-1", "documentation", "done")
    exploit = confirmed_exploit()
    exploit["correlation_id"] = "corr-1"
    insert_exploit(
        conn,
        {
            "id": exploit["exploit_id"],
            "severity": "medium",
            "category": "TM-EX",
            "reproduction_steps": exploit["minimal_sequence"],
            "observed_behavior": exploit["observed_behavior"],
            "expected_behavior": exploit["expected_behavior"],
            "system_version": "aaaaaaa",
        },
        issue_grant("judge"),
    )
    report_id = draft_report(conn, exploit, issue_grant("documentation"))  # type: ignore[arg-type]
    conn.execute("UPDATE reports SET status = 'published' WHERE id = ?", (report_id,))
    conn.execute("UPDATE campaigns SET phase = 'done' WHERE correlation_id = 'corr-1'")
    view = reconstruct(conn, "corr-1")
    assert view["status"] == "incomplete"
    assert any(gap["kind"] == "missing" and "publish_finding" in gap["what"] for gap in view["gaps"])


def test_an_earlier_timestamp_on_a_later_row_is_an_order_violation() -> None:
    conn = _conn()
    log_run(conn, "corr-1", "orchestrator", "done")
    conn.execute("UPDATE run_logs SET started_at = '2026-10-20T00:00:02Z' WHERE id = 1")
    log_run(conn, "corr-1", "judge", "done")
    conn.execute("UPDATE run_logs SET started_at = '2026-10-20T00:00:01Z' WHERE id = 2")
    view = reconstruct(conn, "corr-1")
    assert view["status"] == "incomplete"
    assert any(gap["kind"] == "order_violation" for gap in view["gaps"])


def test_phi_in_a_label_fails_closed() -> None:
    conn = _conn()
    exploit = confirmed_exploit()
    exploit["correlation_id"] = "corr-1"
    insert_exploit(
        conn,
        {
            "id": "exp-1",
            "severity": "high",
            "category": "TM-EX",
            "reproduction_steps": exploit["minimal_sequence"],
            "observed_behavior": "refused",
            "expected_behavior": "refuse",
            "system_version": "aaaaaaa",
        },
        issue_grant("judge"),
    )
    report_id = draft_report(conn, exploit, issue_grant("documentation"))  # type: ignore[arg-type]
    conn.execute("UPDATE reports SET status = 'published' WHERE id = ?", (report_id,))
    conn.execute(
        """
        INSERT INTO approval_events (report_id, purpose, approved_by, bound, decision, recorded_at)
        VALUES (?, 'publish_finding', 'ssn 123-45-6789', 'high', 'published', '2026-10-20T00:00:00Z')
        """,
        (report_id,),
    )
    with pytest.raises(PhiRefused):
        reconstruct(conn, "corr-1")


def test_a_rejection_for_another_call_does_not_satisfy_this_one() -> None:
    conn = _conn()
    p6_campaign(conn, "corr-1")
    conn.execute(
        """
        INSERT INTO dispatch_journal (
            correlation_id, step_no, attempt, call_id, role, kind, intent_hash, state,
            reserved_usd, incurred_usd, settlement, created_at, updated_at
        ) VALUES (
            'corr-1', 1, 1, 'call-wanted', 'red_team', 'model', ?, 'completed',
            0, 0, 'settled', '2026-10-20T00:00:00Z', '2026-10-20T00:00:00Z'
        )
        """,
        ("a" * 64,),
    )
    conn.execute(
        """
        INSERT INTO content_rejections (correlation_id, call_id, reason, recorded_at)
        VALUES ('corr-1', 'call-other', 'rejected_model_output', '2026-10-20T00:00:00Z')
        """
    )
    view = reconstruct(conn, "corr-1")
    assert view["status"] == "incomplete"
    assert any(gap["what"] == "run_logs for call-wanted" for gap in view["gaps"])
    conn.execute(
        """
        INSERT INTO content_rejections (correlation_id, call_id, reason, recorded_at)
        VALUES ('corr-1', 'call-wanted', 'rejected_model_output', '2026-10-20T00:00:01Z')
        """
    )
    matched = reconstruct(conn, "corr-1")
    assert not any("call-wanted" in gap["what"] for gap in matched["gaps"])


def test_a_done_handoff_without_runs_is_missing() -> None:
    conn = _conn()
    observe_version(conn, "aaaaaaa", identity_verified=True, correlation_id="corr-1")
    observe_version(conn, "bbbbbbb", identity_verified=True, correlation_id="corr-1")
    conn.execute("UPDATE version_handoffs SET status = 'done', claimed_by = 'corr-1'")
    conn.execute("UPDATE regression_jobs SET status = 'done', claimed_by = 'corr-1'")
    view = reconstruct(conn, "corr-1")
    assert any(gap["what"] == "regression_runs" for gap in view["gaps"])
