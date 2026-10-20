"""Role grants are issued by trusted boundaries. A role string is not a grant.

A non-blank approved_by is stored as a label. This file does not claim that label was authenticated.
"""

from __future__ import annotations

import sqlite3
from datetime import date
from pathlib import Path

import pytest

from agentforge.agents.approval import ApprovalRefused, decide, load_gate_approvals, submit_for_approval
from agentforge.agents.documentation import draft_report
from agentforge.store.access import GrantRefused, issue_grant
from agentforge.store.migrate import migrate
from agentforge.store.records import insert_exploit
from tests.fixtures import confirmed_exploit

ROOT = Path(__file__).resolve().parents[1]
AGENT_MODULES = (
    "red_team.py",
    "red_team_generator.py",
    "judge.py",
    "documentation.py",
    "openrouter.py",
    "model_output.py",
)
FORBIDDEN = ("issue_grant", "open_campaign", "observe_version", "claim_handoff", "run_suite")


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys = ON")
    migrate(conn)
    return conn


def _record() -> dict[str, object]:
    return {
        "id": "exp-1",
        "severity": "high",
        "category": "TM-PI",
        "reproduction_steps": "turn 1: ask",
        "observed_behavior": "refused",
        "expected_behavior": "refuse",
        "system_version": "aaaaaaa",
        "actor": "judge",
        "role": "judge",
        "approved_by": "forged",
    }


def test_a_forged_role_string_does_not_write() -> None:
    conn = _conn()
    with pytest.raises(GrantRefused):
        insert_exploit(conn, _record())
    with pytest.raises(GrantRefused):
        insert_exploit(conn, _record(), None)
    assert conn.execute("SELECT COUNT(*) FROM exploits").fetchone()[0] == 0


def test_orchestrator_and_red_team_have_no_grant() -> None:
    for role in ("orchestrator", "red_team", "human"):
        with pytest.raises(GrantRefused):
            issue_grant(role)


def test_agent_modules_do_not_import_privileged_entrypoints() -> None:
    root = ROOT / "src" / "agentforge" / "agents"
    for name in AGENT_MODULES:
        text = (root / name).read_text(encoding="utf-8")
        for token in FORBIDDEN:
            assert token not in text, f"{name} imports {token}"


def test_a_blank_label_cannot_publish(tmp_path: Path) -> None:
    conn = _conn()
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
        issue_grant("judge"),
    )
    report_id = draft_report(conn, exploit, issue_grant("documentation"))  # type: ignore[arg-type]
    submit_for_approval(conn, report_id)
    path = tmp_path / "approval.yaml"
    path.write_text(
        f"""approvals:
  - approved_by: " "
    approved_on: 2026-10-19
    purpose: publish_finding
    report_id: {report_id}
    bound: high
""",
        encoding="utf-8",
    )
    with pytest.raises(ApprovalRefused):
        decide(conn, report_id, "published", load_gate_approvals(path), today=date(2026, 10, 19))
    assert conn.execute("SELECT status FROM reports").fetchone()[0] == "pending_approval"


def test_a_well_formed_label_is_stored_and_is_not_called_authentication(tmp_path: Path) -> None:
    conn = _conn()
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
    stored = conn.execute("SELECT approved_by, purpose FROM approval_events").fetchone()
    assert stored == ("operator-label", "publish_finding")
    # The stored name is the file label. This test does not check that a person was present.
