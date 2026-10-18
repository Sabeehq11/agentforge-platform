"""Validate a message against a published v1 JSON Schema.

Uses the pinned jsonschema library (Draft 2020-12). A hand-rolled checker is not used: nested required fields,
types, enums and additionalProperties, including inside $ref and array items, are the contract.

No network. The schema directory is local files. Format checks (date-time) are enforced.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

CONTRACTS = Path(__file__).resolve().parents[3] / "contracts" / "v1"
MESSAGES = ("campaign_request", "attack_result", "verdict", "confirmed_exploit")
ERRORS = (
    "target_unreachable",
    "budget_exceeded",
    "judge_timeout",
    "no_findings_in_window",
    "regression_detected",
)


# jsonschema 4.26 FormatChecker does not ship a date-time checker. The schema still says format date-time, so the
# check lives here rather than being dropped from the schema.
_DATE_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$")


def _check_date_time(value: object) -> bool:
    if not isinstance(value, str) or _DATE_TIME.fullmatch(value) is None:
        return False
    datetime.fromisoformat(value.replace("Z", "+00:00"))
    return True


class ContractError(ValueError):
    """A message does not match its published schema. The path says where."""

    def __init__(self, name: str, detail: str) -> None:
        self.name = name
        super().__init__(f"{name}: {detail}")


def schema_path(name: str) -> Path:
    if name in MESSAGES:
        return CONTRACTS / f"{name}.schema.json"
    if name in ERRORS:
        return CONTRACTS / "errors" / f"{name}.schema.json"
    raise ContractError(name, "unknown schema")


@lru_cache(maxsize=1)
def _registry() -> Registry[Any]:
    resources = []
    for path in sorted(CONTRACTS.rglob("*.schema.json")):
        contents = json.loads(path.read_text(encoding="utf-8"))
        resource = Resource.from_contents(contents, default_specification=DRAFT202012)
        resources.append((contents["$id"], resource))
        resources.append((path.name, resource))
    return Registry().with_resources(resources)


def _checker() -> FormatChecker:
    checker = FormatChecker()
    checker.checks("date-time")(_check_date_time)
    return checker


def _validator(name: str) -> Draft202012Validator:
    schema = json.loads(schema_path(name).read_text(encoding="utf-8"))
    return Draft202012Validator(schema, registry=_registry(), format_checker=_checker())


def validate(name: str, instance: Any) -> None:
    """Raise ContractError if instance does not match the named v1 schema. Returns nothing on success."""
    try:
        _validator(name).validate(instance)
    except ValidationError as exc:
        where = "/".join(str(p) for p in exc.absolute_path) or "(root)"
        raise ContractError(name, f"{where}: {exc.message}") from exc
