"""Offline model-selection comparison. Scores committed fixture responses only.

Does not call a provider, does not read a key, and does not replace config/models.yaml. A real probe remains
an operator step under an approval token. M-12 stays unmet until that happens.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ProbeError(Exception):
    pass


@dataclass(frozen=True)
class ProbeRow:
    role: str
    family: str
    fixture: str
    fixture_usd: float


def load_probe(path: Path) -> tuple[ProbeRow, ...]:
    data: Any = json.loads(path.read_text(encoding="utf-8"))
    rows = data.get("candidates") if isinstance(data, dict) else None
    if not isinstance(rows, list) or not rows:
        raise ProbeError("probe file needs a candidates list")
    parsed: list[ProbeRow] = []
    for raw in rows:
        if not isinstance(raw, dict):
            raise ProbeError("candidate is not an object")
        fixture = str(raw.get("fixture"))
        if fixture not in ("refused", "completed"):
            raise ProbeError("fixture must be refused or completed")
        parsed.append(
            ProbeRow(
                role=str(raw["role"]),
                family=str(raw["family"]),
                fixture=fixture,
                fixture_usd=float(raw["fixture_usd"]),
            )
        )
    families = {row.family for row in parsed}
    if len(families) < 2:
        raise ProbeError("probe candidates must not share one family")
    return tuple(parsed)


def summarize(rows: tuple[ProbeRow, ...]) -> dict[str, int | float]:
    """Count fixture refusals and completions. USD is the fixture amount, not a bill."""
    return {
        "refused": sum(1 for row in rows if row.fixture == "refused"),
        "completed": sum(1 for row in rows if row.fixture == "completed"),
        "fixture_usd": sum(row.fixture_usd for row in rows),
    }
