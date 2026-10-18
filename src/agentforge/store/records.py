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
                record["reproduction_steps"],
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
