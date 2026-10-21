"""Verified execution provenance for a report. The label comes from what was sent, not from one flag.

fake_transport=False alone never produces a live label. The facts are recorded by SessionClient at send time
(see evals/session.py SendFact) and are cross-checked here against rows the journal already wrote. Nothing is
persisted by this module and nothing here can allow or refuse a call.

Three labels:
- fixture: no facts, or every fact came through a fake transport. Every dry run and every test today.
- recorded_verified: every check below holds.
- unverified: anything between. The failing checks are named.

recorded_verified is proven only on constructed facts while LIVE_ENABLED is false, because the real transport is
refused. The first end-to-end proof belongs to a later, separately approved live checkpoint.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from agentforge.evals.session import SendFact

FIXTURE = "fixture"
UNVERIFIED = "unverified"
VERIFIED = "recorded_verified"


@dataclass(frozen=True)
class Provenance:
    label: str
    failed: tuple[str, ...] = ()
    transcript_id: str = ""
    sequence_id: str = ""
    steps: int = 0
    pin: str = ""
    origin: str = ""


FIXTURE_PROVENANCE = Provenance(FIXTURE)


def verify_execution_provenance(
    conn: sqlite3.Connection,
    correlation_id: str,
    sequence_id: str,
    transcript: dict[str, Any] | None,
    facts: Sequence[SendFact],
    pin: str,
    *,
    resumed: bool = False,
) -> Provenance:
    """Classify one executed sequence. Returns a label and the names of the checks that failed."""
    if not facts or all(fact.fake_transport for fact in facts):
        return FIXTURE_PROVENANCE
    failed: list[str] = []
    if any(fact.fake_transport for fact in facts):
        failed.append("fake_transport_fact")
    if not all(fact.transport_is_real for fact in facts):
        failed.append("transport_not_real")
    if not all(fact.live_enabled for fact in facts):
        failed.append("live_flag_off_at_send")
    if resumed:
        failed.append("resumed_sequence")
    purposes = [fact.purpose for fact in facts]
    if "chat" not in purposes:
        failed.append("no_chat_fact")
    elif "identity" not in purposes[: purposes.index("chat")]:
        failed.append("identity_not_before_first_chat")
    origins = {fact.origin for fact in facts}
    if len(origins) != 1:
        failed.append("mixed_origin")
    transcript_id = ""
    user_turns = 0
    if not isinstance(transcript, dict) or not transcript.get("transcript_id"):
        failed.append("no_transcript")
    else:
        transcript_id = str(transcript["transcript_id"])
        user_turns = sum(
            1 for turn in transcript.get("turns", []) if isinstance(turn, dict) and turn.get("role") == "user"
        )
    steps = _completed_steps(conn, correlation_id, sequence_id, failed, expected=user_turns + 1)
    if not _pin_recorded(conn, pin):
        failed.append("pin_not_recorded")
    if failed:
        return Provenance(UNVERIFIED, tuple(failed), transcript_id, sequence_id, steps, pin, _one(origins))
    return Provenance(VERIFIED, (), transcript_id, sequence_id, steps, pin, _one(origins))


def _one(origins: set[str]) -> str:
    return sorted(origins)[0] if origins else ""


def _completed_steps(
    conn: sqlite3.Connection, correlation_id: str, sequence_id: str, failed: list[str], *, expected: int
) -> int:
    """Setup plus one per user turn, each with its latest attempt completed and no unknown row for the sequence."""
    rows = conn.execute(
        """
        SELECT step_no, attempt, state FROM dispatch_journal
        WHERE correlation_id = ? AND sequence_id = ? AND kind = 'target'
        ORDER BY step_no, attempt
        """,
        (correlation_id, sequence_id),
    ).fetchall()
    if any(str(state) == "unknown" for _step, _attempt, state in rows):
        failed.append("journal_unknown_row")
    latest: dict[int, str] = {}
    for step, _attempt, state in rows:
        latest[int(step)] = str(state)
    completed = sum(1 for state in latest.values() if state == "completed")
    if completed != len(latest):
        failed.append("journal_step_not_completed")
    if completed != expected:
        failed.append("journal_step_count_mismatch")
    return completed


def _pin_recorded(conn: sqlite3.Connection, pin: str) -> bool:
    if not pin:
        return False
    row = conn.execute(
        "SELECT 1 FROM version_baselines WHERE target_pin = ? UNION SELECT 1 FROM version_handoffs WHERE target_pin = ?",
        (pin, pin),
    ).fetchone()
    return row is not None
