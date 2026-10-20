"""Validated security signals. A signal is persisted evidence of a Judge finding, never an agent claim.

A signal is recorded only when all of these hold: the Judge returned a Verdict (fail or partial) or a
ConfirmedExploit, the transcript passed validate() and was recorded by the executor, every correlation ID matches
the campaign, the Judge's evidence points at that exact transcript, and the transcript holds a target turn (the
target call completed). Not signals: a pass, any ErrorEnvelope, a refused or unknown-outcome call (no target turn)
and a Red Team claim, which is not an input here at all. A finding counts once, by dedup key.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from agentforge.agents.judge import TranscriptRejected, require_transcript, target_text
from agentforge.agents.novelty import normalize
from agentforge.contracts.messages import AttackResult
from agentforge.orchestrator.journal import sha256_hex
from agentforge.orchestrator.state import bump, now_iso


def dedup_key(category: str, subcategory: str, evidence_text: str) -> str:
    return f"{category}|{subcategory}|{sha256_hex(normalize(evidence_text))}"


def _verdict_of(judged: Any) -> str | None:
    """fail, partial, or None when the Judge output is not a finding."""
    if not isinstance(judged, dict) or "error_code" in judged:
        return None
    if "exploit_id" in judged:
        return "fail" if judged.get("status") == "draft" else None
    outcome = judged.get("verdict")
    return str(outcome) if outcome in ("fail", "partial") else None


def record_signal(
    conn: sqlite3.Connection,
    result: AttackResult,
    judged: Any,
    transcript_raw: object,
    *,
    parent_id: int | None = None,
    depth: int = 0,
) -> int | None:
    """Persist one signal and count it once. Returns the new signal id, or None when nothing was recorded."""
    outcome = _verdict_of(judged)
    if outcome is None:
        return None
    try:
        transcript = require_transcript(transcript_raw)
    except TranscriptRejected:
        return None
    correlation_id = result["correlation_id"]
    if not (transcript.correlation_id == judged.get("correlation_id", correlation_id) == correlation_id):
        return None
    if conn.execute("SELECT 1 FROM campaigns WHERE correlation_id = ?", (correlation_id,)).fetchone() is None:
        return None
    reference = f"transcript:{transcript.transcript_id}"
    if "exploit_id" in judged:
        if judged["exploit_id"] != f"exp-{transcript.transcript_id}"[:64]:
            return None
    elif reference not in judged.get("evidence_refs", []):
        return None
    evidence = target_text(transcript)
    if evidence is None:
        return None
    key = dedup_key(result["category"], result["subcategory"], evidence)
    with conn:
        cursor = conn.execute(
            """
            INSERT OR IGNORE INTO signals (correlation_id, category, subcategory, verdict, evidence_hash, dedup_key,
                transcript_id, transcript_json, parent_id, depth, recorded_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                correlation_id, result["category"], result["subcategory"], outcome, sha256_hex(normalize(evidence)),
                key, transcript.transcript_id, json.dumps(transcript.as_dict(), sort_keys=True), parent_id, depth,
                now_iso(),
            ),
        )
        if cursor.rowcount == 0:
            return None
        bump(conn, correlation_id, "signal_count", commit=False)
    return int(cursor.lastrowid or 0)


def signal_count(conn: sqlite3.Connection, correlation_id: str) -> int:
    row = conn.execute("SELECT COUNT(*) FROM signals WHERE correlation_id = ?", (correlation_id,)).fetchone()
    return int(row[0])
