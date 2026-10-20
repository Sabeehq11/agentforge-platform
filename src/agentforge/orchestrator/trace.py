"""Read-only correlation trace. Joins the campaign, the journal, run_logs, signals and the ledger.

Roles come from real rows only. dispatch_journal carries an external effect. run_logs carries an agent that ran.
run_logs has no `executor` value, so that step is logged there as `harness` and reported as executor. A role with
neither row is omitted. Documentation is not a P6 role and must not appear.
"""

from __future__ import annotations

import sqlite3
from typing import Any

P6_ROLES = ("orchestrator", "red_team", "executor", "judge")


def trace(conn: sqlite3.Connection, correlation_id: str) -> dict[str, Any]:
    """The ordered chain for one campaign. Read only. Raises nothing for a missing id; the campaign is None."""
    campaign = conn.execute("SELECT * FROM campaigns WHERE correlation_id = ?", (correlation_id,)).fetchone()
    columns = [d[0] for d in conn.execute("SELECT * FROM campaigns LIMIT 0").description or []]
    journal = [
        {"call_id": r[0], "role": r[1], "kind": r[2], "state": r[3], "http_status": r[4], "detail": r[5]}
        for r in conn.execute(
            "SELECT call_id, role, kind, state, http_status, detail FROM dispatch_journal WHERE correlation_id = ? ORDER BY id",
            (correlation_id,),
        )
    ]
    logs = [
        {"role": r[0], "state": r[1], "error_code": r[2]}
        for r in conn.execute(
            "SELECT agent_role, state, error_code FROM run_logs WHERE correlation_id = ? ORDER BY id",
            (correlation_id,),
        )
    ]
    signals = conn.execute("SELECT COUNT(*) FROM signals WHERE correlation_id = ?", (correlation_id,)).fetchone()
    spend = [
        {"call_id": r[0], "role": r[1], "state": r[2]}
        for r in conn.execute(
            """
            SELECT s.call_id, s.agent_role, s.state FROM agent_spend s
            JOIN dispatch_journal j ON j.call_id = s.call_id
            WHERE j.correlation_id = ? ORDER BY j.id
            """,
            (correlation_id,),
        )
    ]
    # Journal roles are the external effects. run_logs roles are the agents that ran. harness is the executor,
    # because run_logs has no executor value. A role is listed only when one of those rows recorded it.
    log_role = {"harness": "executor"}
    seen = [row["role"] for row in journal]
    seen += [log_role.get(row["role"], row["role"]) for row in logs]
    present = {role for role in seen if role in P6_ROLES}
    roles = tuple(role for role in P6_ROLES if role in present)
    return {
        "correlation_id": correlation_id,
        "campaign": None if campaign is None else dict(zip(columns, campaign, strict=False)),
        "journal": journal,
        "run_logs": logs,
        "signal_count": int(signals[0]) if signals else 0,
        "spend": spend,
        "roles": roles,
        "documentation_present": any(row["role"] == "documentation" for row in journal + logs),
    }


P7_AGENTS = ("orchestrator", "red_team", "judge", "documentation")


def trace_agents(conn: sqlite3.Connection, correlation_id: str) -> dict[str, Any]:
    """The four PRD agents plus the executor, all under the campaign correlation id. Read only."""
    base = trace(conn, correlation_id)
    logs = base["run_logs"]
    agents = tuple(role for role in P7_AGENTS if any(row["role"] == role for row in logs))
    reports = [
        str(row[0])
        for row in conn.execute("SELECT id FROM reports WHERE correlation_id = ? ORDER BY id", (correlation_id,))
    ]
    runs = [
        int(row[0])
        for row in conn.execute("SELECT id FROM regression_runs WHERE correlation_id = ? ORDER BY id", (correlation_id,))
    ]
    ids = {correlation_id}
    ids.update(str(row[0]) for row in conn.execute("SELECT correlation_id FROM run_logs WHERE correlation_id = ?", (correlation_id,)))
    return {
        "correlation_id": correlation_id,
        "agents": agents,
        "executor": any(row["role"] == "harness" for row in logs),
        "report_ids": reports,
        "regression_run_ids": runs,
        "one_correlation_id": ids == {correlation_id} or not logs,
    }
