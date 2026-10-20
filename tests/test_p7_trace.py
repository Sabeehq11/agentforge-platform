"""One correlation ID across Orchestrator, Red Team, Judge, Documentation and the executor."""

from __future__ import annotations

import sqlite3

from agentforge.agents.documentation import draft_report
from agentforge.harness.stub_target import StubReply, StubTarget
from agentforge.harness.suite import claim_handoff, run_suite
from agentforge.orchestrator.state import log_run
from agentforge.orchestrator.trace import trace_agents
from agentforge.store.migrate import migrate
from agentforge.store.records import insert_exploit, insert_regression_case
from tests.fixtures import confirmed_exploit

CID = "corr-p7"


def test_four_agents_share_one_correlation_id() -> None:
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys = ON")
    migrate(conn)
    for role in ("orchestrator", "red_team", "judge"):
        log_run(conn, CID, role, "done")
    log_run(conn, CID, "harness", "running")
    exploit = confirmed_exploit()
    exploit["correlation_id"] = CID
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
    draft_report(conn, exploit)  # type: ignore[arg-type]
    insert_regression_case(
        conn,
        case_id="rc-exp-1",
        exploit_id="exp-1",
        category="TM-EX",
        subcategory="TM-EX-3",
        invariant_id="missing_authority",
        expected_safe_behavior="refused",
        system_version="aaaaaaa",
    )
    conn.execute(
        "INSERT INTO version_baselines (target_pin, recorded_at, identity_checked_at, correlation_id) VALUES ('aaaaaaa', '2026-10-19T00:00:00Z', '2026-10-19T00:00:00Z', ?)",
        (CID,),
    )
    conn.execute(
        "INSERT INTO version_handoffs (target_pin, previous_pin, detected_at, status, correlation_id) VALUES ('bbbbbbb', 'aaaaaaa', '2026-10-19T00:00:00Z', 'pending', ?)",
        (CID,),
    )
    handoff = int(conn.execute("SELECT id FROM version_handoffs").fetchone()[0])
    claim_handoff(conn, handoff, CID)
    digest_row = conn.execute("SELECT sequence_hash FROM exploits").fetchone()
    run_suite(conn, handoff, CID, StubTarget({str(digest_row[0]): StubReply(401, "")}))
    found = trace_agents(conn, CID)
    assert found["agents"] == ("orchestrator", "red_team", "judge", "documentation")
    assert found["executor"] is True
    assert found["one_correlation_id"] is True
    assert found["report_ids"] == ["rpt-exp-1"]
    assert len(found["regression_run_ids"]) == 3
    foreign = conn.execute(
        "SELECT COUNT(*) FROM run_logs WHERE correlation_id != ?", (CID,)
    ).fetchone()[0]
    assert foreign == 0
