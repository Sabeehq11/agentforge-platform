"""Version-change handoff. P6 records, P7 replays. Nothing here sends a request or replays a regression case.

observe_version runs only after the live identity check passed. The first verified pin is a baseline: not a change,
no handoff, no regression signal, no ranking effect. A later different verified pin writes exactly one pending
handoff whose previous_pin is the latest known pin. target_pin is unique in both tables, and the check and insert
share one transaction, so a repeated or killed-and-resumed call cannot write a second row.
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass

from agentforge.orchestrator.state import log_run, now_iso

PIN_FORMAT = re.compile(r"^[0-9a-f]{7,40}$")


@dataclass(frozen=True)
class Observation:
    action: str  # baseline | unchanged | handoff | rollback_observed | refused
    target_pin: str
    previous_pin: str | None = None
    detail: str = ""


def _latest_known(conn: sqlite3.Connection) -> str | None:
    row = conn.execute("SELECT target_pin FROM version_handoffs ORDER BY id DESC LIMIT 1").fetchone()
    if row is not None:
        return str(row[0])
    row = conn.execute("SELECT target_pin FROM version_baselines ORDER BY id DESC LIMIT 1").fetchone()
    return None if row is None else str(row[0])


def observe_version(
    conn: sqlite3.Connection,
    observed_pin: str,
    *,
    identity_verified: bool,
    correlation_id: str,
) -> Observation:
    """Record a baseline or a handoff. An unverified check or a malformed pin records nothing."""
    if not identity_verified:
        return Observation("refused", observed_pin, detail="identity was not verified")
    if not isinstance(observed_pin, str) or PIN_FORMAT.fullmatch(observed_pin) is None:
        return Observation("refused", str(observed_pin)[:40], detail="pin failed the format check")
    when = now_iso()
    with conn:
        latest = _latest_known(conn)
        if latest is None:
            conn.execute(
                "INSERT INTO version_baselines (target_pin, recorded_at, identity_checked_at, correlation_id) VALUES (?, ?, ?, ?)",
                (observed_pin, when, when, correlation_id),
            )
            return Observation("baseline", observed_pin)
        if observed_pin == latest:
            return Observation("unchanged", observed_pin)
        seen = conn.execute(
            "SELECT 1 FROM version_handoffs WHERE target_pin = ? UNION SELECT 1 FROM version_baselines WHERE target_pin = ?",
            (observed_pin, observed_pin),
        ).fetchone()
        if seen is not None:
            # A pin that returns reuses its unique row. A note is logged, never a second handoff.
            _note_rollback(conn, correlation_id)
            return Observation("rollback_observed", observed_pin, previous_pin=latest)
        cursor = conn.execute(
            "INSERT INTO version_handoffs (target_pin, previous_pin, detected_at, status, correlation_id) VALUES (?, ?, ?, 'pending', ?)",
            (observed_pin, latest, when, correlation_id),
        )
        conn.execute(
            "INSERT INTO regression_jobs (handoff_id, status, recorded_at) VALUES (?, 'pending', ?)",
            (int(cursor.lastrowid or 0), when),
        )
        return Observation("handoff", observed_pin, previous_pin=latest)


def _note_rollback(conn: sqlite3.Connection, correlation_id: str) -> None:
    """run_logs has no note column and a fixed code set, so the rollback is recorded as a campaign note when one exists."""
    row = conn.execute("SELECT 1 FROM campaigns WHERE correlation_id = ?", (correlation_id,)).fetchone()
    if row is not None:
        conn.execute(
            "UPDATE campaigns SET note = 'rollback_observed', updated_at = ? WHERE correlation_id = ?",
            (now_iso(), correlation_id),
        )
        log_run(conn, correlation_id, "orchestrator", "running", commit=False)


def pending_handoffs(conn: sqlite3.Connection) -> list[tuple[str, str]]:
    """(previous_pin, target_pin) for each pending handoff. Read only. P7 claims them."""
    rows = conn.execute("SELECT previous_pin, target_pin FROM version_handoffs WHERE status = 'pending' ORDER BY id")
    return [(str(r[0]), str(r[1])) for r in rows]
