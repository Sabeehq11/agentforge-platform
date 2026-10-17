from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from agentforge.models_config import ModelsConfigError, load_models, parse_models

ROOT = Path(__file__).resolve().parents[1]


def cfg(red: str = "fam-a", judge: str = "fam-b") -> dict[str, Any]:
    def role(family: str) -> dict[str, str]:
        return {"provider": "p", "model": "m", "family": family}

    return {
        "roles": {
            "red_team": role(red),
            "judge": role(judge),
            "orchestrator": role("fam-c"),
            "documentation": role("fam-c"),
        }
    }


def test_shipped_config_loads() -> None:
    roles = load_models(ROOT / "config" / "models.yaml")
    assert roles["red_team"].family != roles["judge"].family


def test_distinct_families_accepted() -> None:
    assert parse_models(cfg())["judge"].family == "fam-b"


def test_same_family_rejected() -> None:
    with pytest.raises(ModelsConfigError):
        parse_models(cfg("fam-a", "fam-a"))


def test_same_family_case_insensitive() -> None:
    with pytest.raises(ModelsConfigError):
        parse_models(cfg("Fam-A", "fam-a"))


def test_missing_role_rejected() -> None:
    c = cfg()
    del c["roles"]["judge"]
    with pytest.raises(ModelsConfigError):
        parse_models(c)


def test_empty_field_rejected() -> None:
    c = cfg()
    c["roles"]["judge"]["model"] = " "
    with pytest.raises(ModelsConfigError):
        parse_models(c)


def test_missing_key_rejected() -> None:
    c = cfg()
    del c["roles"]["red_team"]["family"]
    with pytest.raises(ModelsConfigError):
        parse_models(c)


def test_not_a_mapping_rejected() -> None:
    with pytest.raises(ModelsConfigError):
        parse_models(["nope"])
