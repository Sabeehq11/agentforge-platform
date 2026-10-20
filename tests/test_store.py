"""Store constraints. Duplicate and incomplete inserts raise the typed error, not sqlite3.IntegrityError."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from agentforge.store.access import grant_for_test
from agentforge.store.migrate import MigrateError, migrate
from agentforge.store.records import DuplicateSequence, IncompleteRecord, StoreError, insert_exploit

ROOT = Path(__file__).resolve().parents[1]


def _open() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys = ON")
    migrate(conn)
    return conn


def _record(**overrides: object) -> dict[str, object]:
    record: dict[str, object] = {
        "id": "exp-1",
        "severity": "high",
        "category": "TM-PI",
        "reproduction_steps": "turn 1: ask; turn 2: ask again",
        "observed_behavior": "the rule was ignored",
        "expected_behavior": "the request is refused",
        "system_version": "9f03654",
    }
    record.update(overrides)
    return record


def test_a_complete_draft_is_inserted() -> None:
    conn = _open()
    assert insert_exploit(conn, _record(), grant_for_test("judge")) == "exp-1"
    row = conn.execute("SELECT status, sequence_hash FROM exploits").fetchone()
    assert row[0] == "draft"
    assert len(row[1]) == 64


def test_duplicate_sequence_is_rejected() -> None:
    conn = _open()
    insert_exploit(conn, _record(), grant_for_test("judge"))
    with pytest.raises(DuplicateSequence):
        insert_exploit(conn, _record(id="exp-2"), grant_for_test("judge"))


def test_whitespace_does_not_make_a_sequence_new() -> None:
    conn = _open()
    insert_exploit(conn, _record(), grant_for_test("judge"))
    with pytest.raises(DuplicateSequence):
        insert_exploit(conn, _record(id="exp-2", reproduction_steps="turn 1: ask;  turn 2: ask again"), grant_for_test("judge"))


@pytest.mark.parametrize("field", ["severity", "category", "reproduction_steps", "observed_behavior", "expected_behavior"])
def test_incomplete_insert_is_rejected(field: str) -> None:
    conn = _open()
    with pytest.raises(IncompleteRecord):
        insert_exploit(conn, _record(**{field: ""}), grant_for_test("judge"))


def test_published_insert_is_rejected() -> None:
    conn = _open()
    with pytest.raises(StoreError, match="human approval"):
        insert_exploit(conn, _record(status="published"), grant_for_test("judge"))


def test_migration_adds_a_field_without_losing_data(tmp_path: Path) -> None:
    note_dir = tmp_path / "Docs" / "migrations"
    sql_dir = tmp_path / "sql"
    note_dir.mkdir(parents=True)
    sql_dir.mkdir()
    (note_dir / "0001-initial.md").write_text("initial", encoding="utf-8")
    (note_dir / "0002-add-column.md").write_text("adds a column", encoding="utf-8")
    (sql_dir / "0002.sql").write_text(
        "ALTER TABLE exploits ADD COLUMN source TEXT NOT NULL DEFAULT 'unspecified';", encoding="utf-8"
    )
    conn = sqlite3.connect(":memory:")
    empty = tmp_path / "empty"
    empty.mkdir()
    assert migrate(conn, migrations=empty, notes=note_dir) == ["0001"]
    insert_exploit(conn, _record(), grant_for_test("judge"))
    before = conn.execute("SELECT id, severity, category, observed_behavior FROM exploits").fetchone()
    assert migrate(conn, migrations=sql_dir, notes=note_dir) == ["0002"]
    row = conn.execute("SELECT id, severity, category, observed_behavior, source FROM exploits").fetchone()
    assert row[:4] == before
    assert row[4] == "unspecified"


def test_a_migration_without_a_note_is_refused(tmp_path: Path) -> None:
    note_dir = tmp_path / "notes"
    sql_dir = tmp_path / "sql"
    note_dir.mkdir()
    sql_dir.mkdir()
    (note_dir / "0001-initial.md").write_text("initial", encoding="utf-8")
    (sql_dir / "0002.sql").write_text("ALTER TABLE exploits ADD COLUMN extra TEXT;", encoding="utf-8")
    conn = sqlite3.connect(":memory:")
    sql_only = tmp_path / "sql-only"
    sql_only.mkdir()
    migrate(conn, migrations=sql_only, notes=note_dir)
    with pytest.raises(MigrateError, match="exactly one note"):
        migrate(conn, migrations=sql_dir, notes=note_dir)


def test_initial_note_exists() -> None:
    notes = list((ROOT / "Docs" / "migrations").glob("0001-*.md"))
    assert len(notes) == 1
