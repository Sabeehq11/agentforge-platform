"""Publication and remediation are separate. Neither applies a patch. A false positive stays draft."""

from __future__ import annotations

import sqlite3
from datetime import date
from pathlib import Path

import pytest

from agentforge.harness.stub_target import StubTarget
from agentforge.agents.approval import (
    ApprovalRefused,
    authorize_remediation,
    decide,
    load_gate_approvals,
    request_remediation,
    submit_for_approval,
)
from agentforge.agents.documentation import draft_report
from agentforge.store.migrate import migrate
from agentforge.store.records import insert_exploit
from tests.fixtures import confirmed_exploit


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys = ON")
    migrate(conn)
    return conn


def _draft(conn: sqlite3.Connection, *, held: bool = False) -> str:
    exploit = confirmed_exploit()
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
    )
    return draft_report(conn, exploit, held=held)  # type: ignore[arg-type]


def _file(tmp_path: Path, purpose: str, report_id: str, bound: str) -> list:
    path = tmp_path / "approval.yaml"
    path.write_text(
        f"""approvals:
  - approved_by: operator
    approved_on: 2026-10-19
    purpose: {purpose}
    report_id: {report_id}
    bound: {bound}
""",
        encoding="utf-8",
    )
    return load_gate_approvals(path)


def test_publish_approval_does_not_authorize_remediation(tmp_path: Path) -> None:
    conn = _conn()
    report_id = _draft(conn)
    submit_for_approval(conn, report_id)
    publish = _file(tmp_path, "publish_finding", report_id, "high")
    decide(conn, report_id, "published", publish, today=date(2026, 10, 19))
    assert conn.execute("SELECT status, remediation_status FROM reports").fetchone() == ("published", "proposed")
    request_remediation(conn, report_id)
    with pytest.raises(ApprovalRefused):
        authorize_remediation(conn, report_id, "authorized", publish, today=date(2026, 10, 19))
    assert conn.execute("SELECT remediation_status FROM reports").fetchone()[0] == "pending_authorization"


def test_remediation_approval_does_not_publish(tmp_path: Path) -> None:
    conn = _conn()
    report_id = _draft(conn)
    digest = conn.execute("SELECT remediation_hash FROM reports").fetchone()[0]
    request_remediation(conn, report_id)
    rem = _file(tmp_path, "authorize_remediation", report_id, digest)
    authorize_remediation(conn, report_id, "authorized", rem, today=date(2026, 10, 19))
    assert conn.execute("SELECT status, remediation_status FROM reports").fetchone() == ("draft", "authorized")
    with pytest.raises(ApprovalRefused):
        decide(conn, report_id, "published", rem, today=date(2026, 10, 19))


def test_authorization_does_not_write_a_target_file_or_call_the_stub(tmp_path: Path) -> None:
    conn = _conn()
    report_id = _draft(conn)
    digest = conn.execute("SELECT remediation_hash FROM reports").fetchone()[0]
    request_remediation(conn, report_id)
    stub = StubTarget()
    repo = tmp_path / "tree"
    repo.mkdir()
    (repo / "src").mkdir()
    before = {path.relative_to(repo) for path in repo.rglob("*")}
    authorize_remediation(
        conn, report_id, "authorized",
        _file(tmp_path, "authorize_remediation", report_id, digest), today=date(2026, 10, 19),
    )
    after = {path.relative_to(repo) for path in repo.rglob("*")}
    assert after == before
    assert stub.calls == []
    assert not any(path.suffix in {".patch", ".diff"} for path in tmp_path.rglob("*"))
    assert conn.execute("SELECT status FROM reports").fetchone()[0] == "draft"


def test_a_false_positive_stays_draft() -> None:
    conn = _conn()
    report_id = _draft(conn, held=True)
    with pytest.raises(ApprovalRefused, match="held"):
        submit_for_approval(conn, report_id)
    assert conn.execute("SELECT status FROM reports").fetchone()[0] == "draft"
