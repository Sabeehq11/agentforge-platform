"""Load and validate seed cases. Not an agent. Does not call the target."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from agentforge.safety.phi import PhiRefused, require_clean

EVALS = Path(__file__).resolve().parents[3] / "evals"
SCHEMA_PATH = EVALS / "schema" / "case.schema.json"
CASES_DIR = EVALS / "cases"
THREAT_MODEL = Path(__file__).resolve().parents[3] / "THREAT_MODEL.md"


class CaseRejected(Exception):
    pass


@dataclass(frozen=True)
class Case:
    case_id: str
    category: str
    subcategory: str
    channel: str
    turns: tuple[str, ...]
    expected_safe_behavior: str
    severity: str
    exploitability: str
    regression_flag: bool
    owasp_id: str
    exercise: str
    grader: str
    canary: str | None = None
    fixture: str | None = None
    notes: str = ""
    evidence_ref: str | None = None
    evidence_id: str | None = None
    expected_grade: str | None = None

    @property
    def needs_target(self) -> bool:
        return self.grader not in {"attack_count", "audit_trace", "rate_limit", "stored_evidence"}


def _validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return Draft202012Validator(schema)


def _defined_subcategories(text: str) -> set[str]:
    found: set[str] = set()
    for line in text.splitlines():
        if line.startswith("#### TM-"):
            found.add(line.removeprefix("#### ").split(".", 1)[0].strip())
    return found


def parse_case(data: dict[str, Any], *, threat_model: str) -> Case:
    try:
        _validator().validate(data)
    except ValidationError as exc:
        raise CaseRejected(exc.message) from exc
    subcategory = str(data["subcategory"])
    if subcategory not in _defined_subcategories(threat_model):
        raise CaseRejected(f"{subcategory} is not defined in THREAT_MODEL.md")
    if not subcategory.startswith(str(data["category"]) + "-"):
        raise CaseRejected("subcategory does not belong to category")
    grader = str(data.get("grader", ""))
    if not grader:
        raise CaseRejected("grader is required")
    turns = tuple(str(turn["content"]) for turn in data["input_sequence"]["turns"])
    if grader == "canary" and not data.get("canary"):
        raise CaseRejected("canary grader needs a canary")
    if grader == "canary" and str(data["canary"]) not in "\n".join(turns):
        raise CaseRejected("canary must appear in the input sequence")
    if grader == "stored_evidence" and not (data.get("evidence_ref") and data.get("evidence_id") and data.get("expected_grade")):
        raise CaseRejected("stored_evidence grader needs evidence_ref, evidence_id and expected_grade")
    fixture = data.get("fixture")
    if fixture is not None:
        path = EVALS / str(fixture)
        if not path.is_file():
            raise CaseRejected(f"fixture missing: {fixture}")
        require_clean(path.read_text(encoding="utf-8"))
    for turn in turns:
        require_clean(turn)
    return Case(
        case_id=str(data["case_id"]),
        category=str(data["category"]),
        subcategory=subcategory,
        channel=str(data["channel"]),
        turns=turns,
        expected_safe_behavior=str(data["expected_safe_behavior"]),
        severity=str(data["severity"]),
        exploitability=str(data["exploitability"]),
        regression_flag=bool(data["regression_flag"]),
        owasp_id=str(data["owasp_id"]),
        exercise=str(data["exercise"]),
        grader=grader,
        canary=str(data["canary"]) if data.get("canary") else None,
        fixture=str(fixture) if fixture else None,
        notes=str(data.get("notes", "")),
        evidence_ref=str(data["evidence_ref"]) if data.get("evidence_ref") else None,
        evidence_id=str(data["evidence_id"]) if data.get("evidence_id") else None,
        expected_grade=str(data["expected_grade"]) if data.get("expected_grade") else None,
    )


def load_cases(directory: Path | None = None, *, threat_model_path: Path | None = None) -> tuple[Case, ...]:
    root = directory or CASES_DIR
    model = (threat_model_path or THREAT_MODEL).read_text(encoding="utf-8")
    cases: list[Case] = []
    seen: set[str] = set()
    for path in sorted(root.glob("*.json")):
        raw: Any = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise CaseRejected(f"{path.name} is not an object")
        try:
            case = parse_case(raw, threat_model=model)
        except PhiRefused as exc:
            raise CaseRejected(f"{path.name}: {exc}") from exc
        if case.case_id in seen:
            raise CaseRejected(f"duplicate case_id {case.case_id}")
        seen.add(case.case_id)
        cases.append(case)
    if not cases:
        raise CaseRejected(f"no cases in {root}")
    return tuple(cases)
