"""Apply schema migrations in order. A migration without its note is refused.

The initial schema is version 0001 and lives in schema.sql. Later versions are pairs: a SQL file in
src/agentforge/store/migrations and a note in Docs/migrations with the same NNNN prefix. Notes are required by
the PRD. This module does not invent a note, and it does not run anything but the SQL it is given.

Database files are created by the caller, in tests or by an operator. None is committed.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = Path(__file__).with_name("schema.sql")
MIGRATIONS = Path(__file__).with_name("migrations")
NOTES = Path(__file__).resolve().parents[3] / "Docs" / "migrations"
INITIAL = "0001"


class MigrateError(Exception):
    """A migration could not be applied. The database is unchanged for that version."""


def _applied(conn: sqlite3.Connection) -> set[str]:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'"
    ).fetchone()
    if row is None:
        return set()
    return {r[0] for r in conn.execute("SELECT version FROM schema_migrations")}


def _note(version: str, notes: Path) -> Path:
    """Find the note. The initial note falls back to the shipped file, so a test can add a later note of its own."""
    matches = sorted(notes.glob(f"{version}-*.md"))
    if version == INITIAL and len(matches) != 1:
        matches = sorted(NOTES.glob(f"{version}-*.md"))
    if len(matches) != 1:
        raise MigrateError(f"migration {version} needs exactly one note in Docs/migrations, found {len(matches)}")
    return matches[0]


def _note_path(note: Path) -> str:
    """Store a repo-relative path when the note lives in the repo, and the name otherwise."""
    try:
        return str(note.relative_to(NOTES.parents[1]))
    except ValueError:
        return note.name


def migrate(
    conn: sqlite3.Connection,
    migrations: Path = MIGRATIONS,
    notes: Path = NOTES,
) -> list[str]:
    """Apply every pending migration inside its own transaction. Returns the versions applied, in order."""
    applied = _applied(conn)
    done: list[str] = []
    if INITIAL not in applied:
        note = _note(INITIAL, notes)
        try:
            with conn:
                conn.executescript(SCHEMA.read_text(encoding="utf-8"))
                conn.execute(
                    "INSERT INTO schema_migrations (version, applied_at, note_path) VALUES (?, ?, ?)",
                    (INITIAL, datetime.now(timezone.utc).isoformat(), _note_path(note)),
                )
        except sqlite3.Error as exc:
            raise MigrateError(f"migration {INITIAL} failed: {exc}") from exc
        done.append(INITIAL)
        applied.add(INITIAL)

    for path in sorted(migrations.glob("[0-9][0-9][0-9][0-9].sql")):
        version = path.stem
        if version in applied:
            continue
        if version <= INITIAL:
            raise MigrateError(f"migration {version} collides with the initial schema")
        note = _note(version, notes)
        try:
            with conn:
                conn.executescript(path.read_text(encoding="utf-8"))
                conn.execute(
                    "INSERT INTO schema_migrations (version, applied_at, note_path) VALUES (?, ?, ?)",
                    (version, datetime.now(timezone.utc).isoformat(), _note_path(note)),
                )
        except sqlite3.Error as exc:
            raise MigrateError(f"migration {version} failed and was rolled back: {exc}") from exc
        done.append(version)
    return done
