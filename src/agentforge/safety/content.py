"""Harmful generated content. Reject the body. Do not replace authorized evidence with a hash.

A rejected model body is not stored. A PHI-shaped sequence is refused entirely. A Judge-confirmed
sequence stays in the exploit and the report. Logs record a fixed reason, never the body.
"""

from __future__ import annotations

import sqlite3

from agentforge.safety.phi import PhiRefused, require_clean

REJECTION_REASONS = frozenset(
    {
        "rejected_model_output",
        "phi_refused",
        "not on allowlist",
        "off-list redirect refused",
    }
)


class ContentRefused(Exception):
    """The body was not stored. The message is a fixed reason and does not include the body."""

    def __init__(self, reason: str) -> None:
        if reason not in REJECTION_REASONS and not reason.startswith("rejected:"):
            reason = "rejected_model_output"
        self.reason = reason[:80]
        super().__init__(self.reason)


def reject_model_body(raw: object) -> None:
    """Drop a rejected model body. Nothing is written. The caller logs the reason only."""
    del raw
    raise ContentRefused("rejected_model_output")


def require_storable_sequence(sequence: object) -> None:
    """Refuse the whole write when the sequence matches a PHI pattern. Do not store a redacted half."""
    if isinstance(sequence, str):
        text = sequence
    else:
        import json

        text = json.dumps(sequence)
    try:
        require_clean(text)
    except PhiRefused as exc:
        raise ContentRefused("phi_refused") from exc


def record_rejection(conn: sqlite3.Connection, correlation_id: str, call_id: str, reason: str) -> None:
    """Append a reason-only audit row for one journal call. The body is not an argument."""
    if not call_id:
        raise ContentRefused("rejected_model_output")
    safe = reason if reason in REJECTION_REASONS or reason.startswith("rejected:") else "rejected_model_output"
    conn.execute(
        """
        INSERT INTO content_rejections (correlation_id, call_id, reason, recorded_at)
        VALUES (?, ?, ?, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        """,
        (correlation_id, call_id, safe[:80]),
    )
