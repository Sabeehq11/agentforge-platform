"""Read-only correlation trace. Joins the campaign, the journal, run_logs, signals and the ledger.

Roles come from real rows only. dispatch_journal carries an external effect. run_logs carries an agent that ran.
run_logs has no `executor` value, so that step is logged there as `harness` and reported as executor. A role with
neither row is omitted. Documentation is not a P6 role and must not appear.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from agentforge.safety.phi import require_clean

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


def reconstruct(conn: sqlite3.Connection, correlation_id: str) -> dict[str, Any]:
    """Ordered evidence for one correlation id. Missing or reversed events are gaps, not invented rows.

    The view holds ids, roles, states, outcomes, sequence hashes and approval labels. It does not hold
    reproduction steps, transcripts, bodies, cookies or passwords. approved_by is a label, not a principal.
    """
    gaps: list[dict[str, str]] = []
    campaign = conn.execute(
        "SELECT phase, halt_reason FROM campaigns WHERE correlation_id = ?", (correlation_id,)
    ).fetchone()
    logs = [
        {"id": int(row[0]), "role": str(row[1]), "state": str(row[2]), "error_code": row[3], "started_at": str(row[4])}
        for row in conn.execute(
            "SELECT id, agent_role, state, error_code, started_at FROM run_logs WHERE correlation_id = ? ORDER BY id",
            (correlation_id,),
        )
    ]
    log_roles = {row["role"] for row in logs}
    if campaign is not None and str(campaign[0]) in ("done", "halted") and "orchestrator" not in log_roles:
        gaps.append({"kind": "missing", "what": "orchestrator run_logs"})
    journal = [
        {"call_id": str(row[0]), "role": str(row[1]), "state": str(row[2])}
        for row in conn.execute(
            "SELECT call_id, role, state FROM dispatch_journal WHERE correlation_id = ? ORDER BY id",
            (correlation_id,),
        )
    ]
    for item in journal:
        rejected = conn.execute(
            "SELECT 1 FROM content_rejections WHERE correlation_id = ? AND call_id = ?",
            (correlation_id, item["call_id"]),
        ).fetchone()
        # The executor step is journaled as executor and logged as harness. run_logs has no executor value.
        logged = "harness" if item["role"] == "executor" else item["role"]
        if logged not in log_roles and rejected is None:
            gaps.append({"kind": "missing", "what": f"run_logs for {item['call_id']}"})
    reports = [
        {
            "id": str(row[0]),
            "status": str(row[1]),
            "remediation_status": str(row[2]),
            "sequence_hash": str(row[3]),
        }
        for row in conn.execute(
            "SELECT id, status, remediation_status, sequence_hash FROM reports WHERE correlation_id = ? ORDER BY id",
            (correlation_id,),
        )
    ]
    for report in reports:
        exploit = conn.execute(
            "SELECT sequence_hash FROM exploits WHERE id = (SELECT exploit_id FROM reports WHERE id = ?)",
            (report["id"],),
        ).fetchone()
        if exploit is None:
            gaps.append({"kind": "missing", "what": f"exploit for {report['id']}"})
        if "documentation" not in log_roles:
            gaps.append({"kind": "missing", "what": f"documentation run_logs for {report['id']}"})
        if report["status"] == "published":
            published = conn.execute(
                "SELECT approved_by FROM approval_events WHERE report_id = ? AND purpose = 'publish_finding'",
                (report["id"],),
            ).fetchone()
            if published is None:
                gaps.append({"kind": "missing", "what": f"publish_finding for {report['id']}"})
            else:
                report["approved_by"] = str(published[0])
        if report["remediation_status"] == "authorized":
            authorized = conn.execute(
                "SELECT 1 FROM approval_events WHERE report_id = ? AND purpose = 'authorize_remediation'",
                (report["id"],),
            ).fetchone()
            if authorized is None:
                gaps.append({"kind": "missing", "what": f"authorize_remediation for {report['id']}"})
    handoff = conn.execute(
        "SELECT id, status FROM version_handoffs WHERE claimed_by = ?", (correlation_id,)
    ).fetchone()
    job = None
    runs = [
        {"id": int(row[0]), "outcome": str(row[1]), "sequence_hash": ""}
        for row in conn.execute(
            """
            SELECT r.id, r.outcome FROM regression_runs r
            WHERE r.correlation_id = ? ORDER BY r.id
            """,
            (correlation_id,),
        )
    ]
    if handoff is not None:
        job_row = conn.execute(
            "SELECT status FROM regression_jobs WHERE handoff_id = ?", (int(handoff[0]),)
        ).fetchone()
        if job_row is None:
            gaps.append({"kind": "missing", "what": "regression job"})
        else:
            job = {"handoff_id": int(handoff[0]), "status": str(job_row[0])}
        if str(handoff[1]) == "done" and not runs:
            gaps.append({"kind": "missing", "what": "regression_runs"})
    previous = ""
    for row in logs:
        if previous and row["started_at"] < previous:
            gaps.append({"kind": "order_violation", "what": f"run_logs {row['id']}"})
        previous = row["started_at"]
    view = {
        "correlation_id": correlation_id,
        "status": "incomplete" if gaps else "complete",
        "gaps": gaps,
        "campaign_phase": None if campaign is None else str(campaign[0]),
        "halt_reason": None if campaign is None else campaign[1],
        "run_logs": logs,
        "journal": journal,
        "reports": reports,
        "job": job,
        "regression_runs": runs,
    }
    require_clean(json.dumps(view))
    return view
