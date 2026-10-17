"""Per-role model configuration (ADR-004). Red Team and Judge must come from different model families."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

REQUIRED_ROLES = ("red_team", "judge", "orchestrator", "documentation")


class ModelsConfigError(ValueError):
    pass


@dataclass(frozen=True)
class RoleModel:
    provider: str
    model: str
    family: str


def parse_models(data: Any) -> dict[str, RoleModel]:
    if not isinstance(data, dict) or not isinstance(data.get("roles"), dict):
        raise ModelsConfigError("models config needs a 'roles' mapping")
    roles: dict[str, RoleModel] = {}
    for name in REQUIRED_ROLES:
        raw = data["roles"].get(name)
        if not isinstance(raw, dict):
            raise ModelsConfigError(f"role {name!r} is missing")
        try:
            roles[name] = RoleModel(
                provider=str(raw["provider"]).strip(),
                model=str(raw["model"]).strip(),
                family=str(raw["family"]).strip().lower(),
            )
        except KeyError as exc:
            raise ModelsConfigError(f"role {name!r} lacks {exc.args[0]!r}") from exc
        if not all((roles[name].provider, roles[name].model, roles[name].family)):
            raise ModelsConfigError(f"role {name!r} has an empty field")
    if roles["red_team"].family == roles["judge"].family:
        raise ModelsConfigError("red_team and judge must use different model families")
    return roles


def load_models(path: str | Path) -> dict[str, RoleModel]:
    return parse_models(yaml.safe_load(Path(path).read_text(encoding="utf-8")))
