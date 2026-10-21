"""Campaign state over SQLite. A phase change and its run_logs row are written in one transaction.

Plain Python, no queue, no framework. run_logs is an append-only audit trail and its CHECKs are not altered, so the
executor step is logged with the existing role 'harness'. dispatch_journal.role carries the true role.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any

from agentforge.contracts.messages import CampaignRequest
from agentforge.contracts.validate import ContractError

PHASES = ("selecting", "attacking", "judging", "recording", "done", "halted")
_RUN_STATE = {"selecting": "queued", "attacking": "running", "judging": "running", "recording": "running", "done": "done", "halted": "halted"}
RUN_LOG_ROLES = ("orchestrator", "red_team", "judge", "documentation", "harness")
ERROR_CODES = ("target_unreachable", "budget_exceeded", "judge_timeout", "no_findings_in_window", "regression_detected")


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class CampaignOpen(Exception):
    """A campaign is already open. Execution is sequential, so a second enqueue is refused as budget_exceeded."""


def log_run(
    conn: sqlite3.Connection,
    correlation_id: str,
    role: str,
    state: str,
    *,
    error_code: str | None = None,
    commit: bool = True,
) -> None:
    """Append one run_logs row. Does not commit when the caller owns the transaction."""
    if role not in RUN_LOG_ROLES:
        raise ValueError(f"unknown run_logs role {role}")
    when = now_iso()
    conn.execute(
        "INSERT INTO run_logs (correlation_id, agent_role, state, error_code, started_at, finished_at) VALUES (?, ?, ?, ?, ?, ?)",
        (correlation_id, role, state, error_code, when, when if state in ("halted", "done") else None),
    )
    if commit:
        conn.commit()


def open_campaign(
    conn: sqlite3.Connection,
    request: CampaignRequest,
    *,
    system_version: str,
    category_pinned: bool = True,
    requested_mode: str | None = None,
) -> None:
    """Insert a campaign row in phase selecting. Refuses a second open campaign and a reused correlation id.

    category_pinned defaults to true so an existing caller still attacks request["category"]. A false value
    keeps that category as a valid placeholder. Rank chooses the first attack. requested_mode is None for the
    one-turn default or "multi_turn"; it is stored so a resume keeps it. It is not a contract field.
    """
    if requested_mode not in (None, "multi_turn"):
        raise ValueError("requested_mode must be None or multi_turn")
    row = conn.execute("SELECT correlation_id FROM campaigns WHERE phase NOT IN ('done', 'halted') LIMIT 1").fetchone()
    if row is not None and row[0] != request["correlation_id"]:
        raise CampaignOpen("a campaign is already open")
    when = now_iso()
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO campaigns (
                    correlation_id, request_json, phase, system_version, category_pinned, requested_mode,
                    created_at, updated_at
                ) VALUES (?, ?, 'selecting', ?, ?, ?, ?, ?)
                """,
                (
                    request["correlation_id"], json.dumps(request, sort_keys=True), system_version,
                    1 if category_pinned else 0, requested_mode, when, when,
                ),
            )
            log_run(conn, request["correlation_id"], "orchestrator", "queued", commit=False)
    except sqlite3.IntegrityError as exc:
        raise ContractError("campaign_request", "correlation_id was already used") from exc


def get_campaign(conn: sqlite3.Connection, correlation_id: str) -> dict[str, Any] | None:
    cursor = conn.execute("SELECT * FROM campaigns WHERE correlation_id = ?", (correlation_id,))
    row = cursor.fetchone()
    if row is None:
        return None
    return dict(zip([d[0] for d in cursor.description], row, strict=True))


def require_campaign(conn: sqlite3.Connection, correlation_id: str) -> dict[str, Any]:
    found = get_campaign(conn, correlation_id)
    if found is None:
        raise ContractError("campaign_request", f"no campaign {correlation_id}")
    return found


def request_of(campaign: dict[str, Any]) -> CampaignRequest:
    body: CampaignRequest = json.loads(campaign["request_json"])
    return body


def set_phase(
    conn: sqlite3.Connection,
    correlation_id: str,
    phase: str,
    *,
    role: str = "orchestrator",
    error_code: str | None = None,
) -> None:
    """Change the phase and append the matching run_logs row in one transaction."""
    if phase not in PHASES:
        raise ValueError(f"unknown phase {phase}")
    if error_code is not None and error_code not in ERROR_CODES:
        raise ValueError(f"unknown error code {error_code}")
    with conn:
        conn.execute("UPDATE campaigns SET phase = ?, updated_at = ? WHERE correlation_id = ?", (phase, now_iso(), correlation_id))
        log_run(conn, correlation_id, role, _RUN_STATE[phase], error_code=error_code, commit=False)


def halt(
    conn: sqlite3.Connection,
    correlation_id: str,
    error_code: str,
    detail: str,
    *,
    retryable: bool,
    next_attempt_at: str | None = None,
    role: str = "orchestrator",
) -> None:
    """Halt a campaign with a typed code. The row is resumable only when retryable."""
    if error_code not in ERROR_CODES:
        raise ValueError(f"unknown error code {error_code}")
    with conn:
        conn.execute(
            """
            UPDATE campaigns SET phase = 'halted', halt_reason = ?, retryable = ?, next_attempt_at = ?, note = ?, updated_at = ?
            WHERE correlation_id = ?
            """,
            (error_code, 1 if retryable else 0, next_attempt_at, detail[:500], now_iso(), correlation_id),
        )
        log_run(conn, correlation_id, role, "halted", error_code=error_code, commit=False)


def resume_campaign(conn: sqlite3.Connection, correlation_id: str) -> dict[str, Any]:
    """Reopen a retryable halted campaign in phase selecting. A non-retryable halt stays closed."""
    campaign = require_campaign(conn, correlation_id)
    if campaign["phase"] != "halted":
        return campaign
    if not campaign["retryable"]:
        raise CampaignOpen("campaign halted with retryable=false and cannot be resumed")
    with conn:
        conn.execute(
            "UPDATE campaigns SET phase = 'selecting', halt_reason = NULL, retryable = 0, next_attempt_at = NULL, updated_at = ? WHERE correlation_id = ?",
            (now_iso(), correlation_id),
        )
        log_run(conn, correlation_id, "orchestrator", "queued", commit=False)
    return require_campaign(conn, correlation_id)


def bump(conn: sqlite3.Connection, correlation_id: str, column: str, amount: int = 1, *, commit: bool = True) -> None:
    """Increment one counter column. Only the named counters are allowed."""
    if column not in ("attacks_done", "sequences_started", "turns_sent", "signal_count", "attempt"):
        raise ValueError(f"{column} is not a counter")
    conn.execute(f"UPDATE campaigns SET {column} = {column} + ?, updated_at = ? WHERE correlation_id = ?", (amount, now_iso(), correlation_id))  # nosec B608
    if commit:
        conn.commit()


def set_scores(conn: sqlite3.Connection, correlation_id: str, scores: dict[str, Any]) -> None:
    with conn:
        conn.execute(
            "UPDATE campaigns SET scores_json = ?, updated_at = ? WHERE correlation_id = ?",
            (json.dumps(scores, sort_keys=True), now_iso(), correlation_id),
        )


def set_note(conn: sqlite3.Connection, correlation_id: str, note: str) -> None:
    with conn:
        conn.execute("UPDATE campaigns SET note = ?, updated_at = ? WHERE correlation_id = ?", (note[:500], now_iso(), correlation_id))
