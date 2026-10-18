"""A breaking change under contracts/v1 fails. The same change under a new version directory passes."""

from __future__ import annotations

import json
from pathlib import Path

from scripts.check_schema_diff import breaking, compare


def _schema() -> dict[str, object]:
    return {
        "required": ["message_id", "category"],
        "properties": {
            "message_id": {"type": "string"},
            "category": {"type": "string", "enum": ["TM-PI", "TM-EX"]},
        },
    }


def test_removing_a_required_field_is_breaking() -> None:
    changed = _schema()
    changed["required"] = ["message_id"]
    assert any("required field removed" in p for p in breaking(_schema(), changed))


def test_changing_a_type_is_breaking() -> None:
    changed = _schema()
    changed["properties"]["message_id"] = {"type": "integer"}  # type: ignore[index]
    assert any("type changed" in p for p in breaking(_schema(), changed))


def test_narrowing_an_enum_is_breaking() -> None:
    changed = _schema()
    changed["properties"]["category"] = {"type": "string", "enum": ["TM-PI"]}  # type: ignore[index]
    assert any("enum narrowed" in p for p in breaking(_schema(), changed))


def test_an_optional_field_is_not_breaking() -> None:
    changed = _schema()
    changed["properties"]["note"] = {"type": "string"}  # type: ignore[index]
    assert breaking(_schema(), changed) == []


def test_unbumped_breaking_change_fails_and_a_bumped_copy_passes(tmp_path: Path) -> None:
    original = _schema()
    broken = _schema()
    broken["required"] = ["message_id"]
    rel = "contracts/v1/campaign_request.schema.json"
    assert compare({rel: original}, {rel: broken})

    bumped = "contracts/v2/campaign_request.schema.json"
    # A new directory is a new version. v1 is unchanged, so the v1 comparison is clean.
    assert compare({rel: original}, {rel: original, bumped: broken}) == []
    (tmp_path / "v2").mkdir()
    (tmp_path / "v2" / "campaign_request.schema.json").write_text(json.dumps(broken), encoding="utf-8")
