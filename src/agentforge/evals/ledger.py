"""OWASP coverage ledger checks. The ledger records coverage. It closes no PRD requirement and satisfies nothing."""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from agentforge.evals.cases import EVALS, Case

LEDGER_PATH = EVALS / "owasp_coverage.json"
PRD_IDS = ("A01", "A03", "A04", "A06", "A07", "A09", "A10", "LLM01", "LLM02", "LLM05", "LLM06", "LLM08")
STATUSES = frozenset({"exercised", "offline_only", "partially_exercised", "unverified_property", "platform_scan", "interpretation"})
BANNED_STATUSES = frozenset({"satisfied", "met", "closed"})
GATES = frozenset({"R10", "U1", "U2", "U3", "U4", "U5"})
U_ITEMS = ("U1", "U2", "U3", "U4", "U5")
EVIDENCE_KINDS = frozenset(
    {"local_target", "offline_replay", "response_claim_proxy", "platform_scan", "code_reading", "none", "target"}
)
HOSTS = frozenset({"R7", "R10", "none"})
# The LLM08 outcome is a claim in the answer text. These phrases would say more than that.
LLM08_BANNED = ("tool invoked", "tool use verified", "action blocked")


def load_ledger(path: Path | None = None) -> dict[str, Any]:
    data = json.loads((path or LEDGER_PATH).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("ledger is not an object")
    return data


def _stored_case_ids(results_dir: Path, name: str) -> set[str]:
    path = results_dir / name
    if not path.is_file():
        return set()
    stored = json.loads(path.read_text(encoding="utf-8"))
    return {str(row["case_id"]) for row in stored.get("results", []) if isinstance(row, dict) and "case_id" in row}


def check_ledger(ledger: dict[str, Any], cases: Iterable[Case], results_dir: Path | None = None) -> list[str]:
    """Return every problem found. An empty list means the ledger is internally consistent, not that anything is met."""
    problems: list[str] = []
    cases = tuple(cases)
    by_id = {case.case_id: case for case in cases}
    results = results_dir or (EVALS / "results")
    header = ledger.get("header", {})
    if header.get("closes_no_prd_requirement") is not True:
        problems.append("ledger header must state it closes no PRD requirement")
    if "pass means the invariant was not violated" not in str(header.get("pass_definition", "")):
        problems.append("ledger header must define pass")
    rows = ledger.get("rows", [])
    seen = {str(row.get("id")) for row in rows}
    for item in PRD_IDS:
        if item not in seen:
            problems.append(f"{item} has no ledger row")
    campaign_ids = _stored_case_ids(results, "campaign-latest.json")
    public_files = list(results.glob("public-target-*.json"))
    other = {key: set(value) for key, value in header.get("other_case_owasp_ids", {}).items()}
    for row in rows:
        rid = str(row.get("id"))
        status = str(row.get("status"))
        if status in BANNED_STATUSES:
            problems.append(f"{rid} status {status} is not allowed")
        elif status not in STATUSES:
            problems.append(f"{rid} unknown status {status}")
        if row.get("closed_by") is not None:
            problems.append(f"{rid} closed_by must be null")
        gates = row.get("assigned_gate")
        if not isinstance(gates, list) or not gates:
            if status != "exercised" or row.get("unobserved_half"):
                problems.append(f"{rid} has no assigned_gate")
            gates = []
        for gate in gates:
            if gate not in GATES:
                problems.append(f"{rid} unknown gate {gate}")
        if status == "partially_exercised" and not any(gate in U_ITEMS for gate in gates):
            problems.append(f"{rid} partially exercised row is assigned to R10 alone, which cannot observe its unobserved half")
        if not (status == "exercised" and gates == ["R10"]) and not str(row.get("unobserved_half", "")).strip():
            problems.append(f"{rid} names no unobserved half")
        kind = str(row.get("evidence_kind"))
        if kind not in EVIDENCE_KINDS:
            problems.append(f"{rid} unknown evidence kind {kind}")
        if kind == "target" and not public_files:
            problems.append(f"{rid} claims target evidence and no public-URL result file exists")
        case_ids = [str(item) for item in row.get("case_ids", [])]
        for case_id in case_ids:
            if case_id not in by_id:
                problems.append(f"{rid} names unknown case {case_id}")
        if status == "exercised" and kind not in ("local_target", "target"):
            problems.append(f"{rid} is exercised and has no target outcome; evidence kind {kind} supports offline_only at most")
        if status == "offline_only" and kind != "offline_replay":
            problems.append(f"{rid} offline_only must carry offline_replay evidence, not {kind}")
        if status in ("exercised", "offline_only", "partially_exercised") and not case_ids:
            problems.append(f"{rid} has no case")
        expected = {case.case_id for case in cases if case.owasp_id == rid}
        if set(case_ids) != expected:
            problems.append(f"{rid} case_ids {sorted(case_ids)} do not match the case files {sorted(expected)}")
        if status == "unverified_property" and expected:
            problems.append(f"{rid} is an unverified property and a case file carries its id")
        if kind in ("offline_replay", "response_claim_proxy", "none", "platform_scan", "code_reading") and row.get("target_evidence") != "none":
            problems.append(f"{rid} target_evidence must be none for {kind}")
        if kind == "local_target":
            if row.get("target_evidence") != "local_target":
                problems.append(f"{rid} local_target evidence must say so")
            if not (set(case_ids) & campaign_ids):
                problems.append(f"{rid} claims local_target evidence and no case has a stored outcome")
        if any(by_id[case_id].owasp_id == "LLM08" for case_id in case_ids if case_id in by_id) and kind != "response_claim_proxy":
            problems.append(f"{rid} LLM08 evidence kind must be response_claim_proxy")
    ledger_ids = {str(row.get("id")) for row in rows}
    for case in cases:
        if case.owasp_id not in ledger_ids and case.case_id not in other.get(case.owasp_id, set()):
            problems.append(f"{case.case_id} owasp id {case.owasp_id} is not in the ledger")
    gaps = {str(item.get("id")): item for item in ledger.get("open_gaps", [])}
    for u_id in U_ITEMS:
        gap = gaps.get(u_id)
        if gap is None:
            problems.append(f"{u_id} is missing from open_gaps")
            continue
        if gap.get("status") != "gap":
            problems.append(f"{u_id} status must be gap")
        if gap.get("candidate_host") not in HOSTS:
            problems.append(f"{u_id} candidate_host must be one of R7, R10, none")
        if gap.get("host_scope_amended") is not False:
            problems.append(f"{u_id} host_scope_amended must be false")
        if not gap.get("preconditions"):
            problems.append(f"{u_id} has no preconditions")
    return problems


def llm08_wording_problems(texts: dict[str, str]) -> list[str]:
    """Flag text that describes an LLM08 outcome as more than a response claim."""
    problems: list[str] = []
    for name, text in texts.items():
        lowered = text.lower()
        for phrase in LLM08_BANNED:
            if phrase in lowered:
                problems.append(f"{name} says '{phrase}'")
    return problems
