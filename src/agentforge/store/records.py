"""Insert path for exploit records. Constraints the schema cannot express live here.

The schema rejects a duplicate sequence hash and an empty required field. This module rejects a missing field
before the insert, and rejects status 'published'. Publication is a human act (Docs/ACCESS_CONTROL.md). No agent
calls this. P9 enforces the role split in code.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any

REQUIRED = ("id", "severity", "category", "reproduction_steps", "observed_behavior", "expected_behavior", "system_version")
CATEGORIES = ("TM-PI", "TM-EX", "TM-SC", "TM-TM", "TM-DS", "TM-ID")
SEVERITIES = ("critical", "high", "medium", "low")


class StoreError(Exception):
    """A record was refused. The message names the rule, not the raw database error."""


class IncompleteRecord(StoreError):
    pass


class DuplicateSequence(StoreError):
    pass


def sequence_hash(sequence: Any) -> str:
    """SHA-256 of the sequence with keys sorted and whitespace collapsed, so the same attack cannot be stored twice."""
    canonical = json.dumps(sequence, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    collapsed = " ".join(canonical.split())
    return hashlib.sha256(collapsed.encode("utf-8")).hexdigest()


def insert_regression_case(
    conn: sqlite3.Connection,
    *,
    case_id: str,
    exploit_id: str,
    category: str,
    subcategory: str,
    invariant_id: str,
    expected_safe_behavior: str,
    system_version: str,
) -> str:
    """Insert one case for a confirmed exploit. A second case for the same exploit is a no-op."""
    if not case_id or not exploit_id or not expected_safe_behavior or not system_version:
        raise IncompleteRecord("a regression case needs an id, an exploit, expected behavior and a version")
    if category not in CATEGORIES:
        raise IncompleteRecord("category is not a threat-model id")
    existing = conn.execute("SELECT id FROM regression_cases WHERE exploit_id = ?", (exploit_id,)).fetchone()
    if existing is not None:
        return str(existing[0])
    parent = conn.execute("SELECT 1 FROM exploits WHERE id = ?", (exploit_id,)).fetchone()
    if parent is None:
        raise IncompleteRecord("a regression case needs an exploit the Judge confirmed")
    try:
        conn.execute(
            """
            INSERT INTO regression_cases (
                id, exploit_id, category, expected_safe_behavior, system_version, lifecycle, invariant_id, subcategory
            ) VALUES (?, ?, ?, ?, ?, 'open', ?, ?)
            """,
            (case_id, exploit_id, category, expected_safe_behavior, system_version, invariant_id, subcategory),
        )
    except sqlite3.IntegrityError as exc:
        raise StoreError(f"regression case {case_id} was rejected: {exc}") from exc
    return case_id


def insert_regression_run(
    conn: sqlite3.Connection,
    *,
    case_id: str,
    system_version: str,
    correlation_id: str,
    repeat_index: int,
    outcome: str,
    invariant_id: str,
    http_status: int | None,
    evidence: dict[str, Any],
    recorded_at: str,
) -> int | None:
    """Append one completed repeat. A row that already exists is left unchanged and returns None."""
    if outcome not in ("pass", "fail", "not_exercised", "wording_only"):
        raise IncompleteRecord(f"outcome {outcome!r} is not a regression outcome")
    if not 1 <= repeat_index <= 3:
        raise IncompleteRecord("repeat_index must be 1, 2 or 3")
    found = conn.execute(
        "SELECT id FROM regression_runs WHERE case_id = ? AND system_version = ? AND repeat_index = ?",
        (case_id, system_version, repeat_index),
    ).fetchone()
    if found is not None:
        return None
    try:
        cursor = conn.execute(
            """
            INSERT INTO regression_runs (
                case_id, system_version, correlation_id, repeat_index, outcome, invariant_id,
                http_status, evidence_json, recorded_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                system_version,
                correlation_id,
                repeat_index,
                outcome,
                invariant_id,
                http_status,
                json.dumps(evidence, sort_keys=True),
                recorded_at,
            ),
        )
    except sqlite3.IntegrityError as exc:
        raise StoreError(f"regression run was rejected: {exc}") from exc
    return int(cursor.lastrowid or 0)


def outcomes(conn: sqlite3.Connection, case_id: str, system_version: str) -> list[dict[str, Any]]:
    """The completed repeats for one case and one pin. Read only. Earlier pins are a different call."""
    rows = conn.execute(
        """
        SELECT id, repeat_index, outcome, invariant_id, http_status, evidence_json, correlation_id
        FROM regression_runs WHERE case_id = ? AND system_version = ? ORDER BY repeat_index
        """,
        (case_id, system_version),
    ).fetchall()
    return [
        {
            "id": int(row[0]),
            "repeat_index": int(row[1]),
            "outcome": str(row[2]),
            "invariant_id": str(row[3]),
            "http_status": row[4],
            "evidence": json.loads(row[5]),
            "correlation_id": str(row[6]),
        }
        for row in rows
    ]


def insert_exploit(conn: sqlite3.Connection, record: dict[str, Any]) -> str:
    """Insert a draft exploit. Returns the id. Raises IncompleteRecord or DuplicateSequence, never IntegrityError."""
    missing = [name for name in REQUIRED if not record.get(name)]
    if missing:
        raise IncompleteRecord("missing required field: " + ", ".join(missing))
    if record["severity"] not in SEVERITIES:
        raise IncompleteRecord("severity is not one of " + ", ".join(SEVERITIES))
    if record["category"] not in CATEGORIES:
        raise IncompleteRecord("category is not a threat-model id")
    status = record.get("status", "draft")
    if status == "published":
        raise StoreError("an agent cannot insert a published exploit; publication requires human approval")
    if status not in ("draft", "pending_approval", "rejected"):
        raise StoreError(f"status {status!r} is not allowed on insert")
    digest = sequence_hash(record["reproduction_steps"])
    steps = record["reproduction_steps"]
    if not isinstance(steps, str):
        steps = json.dumps(steps, sort_keys=True, separators=(",", ":"))
    try:
        conn.execute(
            """
            INSERT INTO exploits (
                id, severity, category, reproduction_steps, observed_behavior, expected_behavior,
                sequence_hash, system_version, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record["id"],
                record["severity"],
                record["category"],
                steps,
                record["observed_behavior"],
                record["expected_behavior"],
                digest,
                record["system_version"],
                status,
            ),
        )
    except sqlite3.IntegrityError as exc:
        if "sequence_hash" in str(exc):
            raise DuplicateSequence("an exploit with this attack sequence already exists") from exc
        raise StoreError(f"exploit {record['id']} was rejected: {exc}") from exc
    return str(record["id"])
