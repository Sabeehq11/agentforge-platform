"""Deterministic executor. Not an agent. Does not implement the protocols in agents.interfaces.

Dry-run is the default. It writes pass only for the local attack-count grader. Every case that needs a target
response is not_run. Unexecuted, refused and inconclusive cases are never pass.

Live mode still goes through the chokepoint. While LIVE_ENABLED is false, a non-fake transport is refused and the
case is not_run. This module does not set LIVE_ENABLED and does not read an environment flag to do so.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import urljoin
from datetime import date
from pathlib import Path
from typing import Any, Literal

from agentforge.evals.cases import Case, load_cases
from agentforge.evals.login import LoginRequest
from agentforge.evals.graders import (
    grade_attack_count,
    grade_canary,
    grade_missing_authority,
    grade_patient_boundary,
    phi_kinds,
    unexpected_tool,
)
from agentforge.evals.session import CHAT_PATH, SessionClient, SessionError
from agentforge.safety.allowlist import Allowlist
from agentforge.safety.budget import Budget, BudgetError
from agentforge.safety.chokepoint import LIVE_ENABLED, RefusedByChokepoint, Response, Transport, request
from agentforge.safety.identity import IdentityMismatch
from agentforge.safety.phi import PhiRefused, require_clean
from agentforge.safety.rate import RateCap
from agentforge.safety.refusal_log import RefusalLog
from agentforge.safety.spend_limits import Attestation

Outcome = Literal["pass", "fail", "not_run", "error"]
_OUTCOMES = ("pass", "fail", "not_run", "error")


@dataclass(frozen=True)
class CaseResult:
    case_id: str
    category: str
    subcategory: str
    owasp_id: str
    exercise: str
    outcome: Outcome
    detail: str

    def as_dict(self) -> dict[str, str]:
        return {
            "case_id": self.case_id,
            "category": self.category,
            "subcategory": self.subcategory,
            "owasp_id": self.owasp_id,
            "exercise": self.exercise,
            "outcome": self.outcome,
            "detail": self.detail,
        }


def _result(case: Case, outcome: Outcome, detail: str) -> CaseResult:
    if outcome not in _OUTCOMES:
        raise ValueError(f"unknown outcome {outcome}")
    return CaseResult(
        case.case_id, case.category, case.subcategory, case.owasp_id, case.exercise, outcome, detail
    )


def summarize(results: tuple[CaseResult, ...]) -> dict[str, int]:
    counts = {name: 0 for name in _OUTCOMES}
    for item in results:
        counts[item.outcome] += 1
    return counts


def run_dry(cases: tuple[Case, ...] | None = None, *, budget: Budget | None = None) -> tuple[CaseResult, ...]:
    """No transport. Local cap-stop may pass. Everything else is not_run."""
    selected = cases if cases is not None else load_cases()
    out: list[CaseResult] = []
    for case in selected:
        if case.grader == "attack_count":
            out.append(_grade_cap(case, budget))
            continue
        out.append(_result(case, "not_run", "dry-run does not call the target"))
    return tuple(out)


def _grade_cap(case: Case, budget: Budget | None) -> CaseResult:
    """Fill the attack-count cap with zero-cost reservations, then require the next one to stop.

    This grades the platform cap, not the target. It does not call a transport. A missing or unapproved budget
    is not_run, not a pass.
    """
    if budget is None:
        return _result(case, "not_run", "no budget was supplied to grade the cap")
    cap = budget.caps.max_attacks_per_run
    try:
        while budget.attacks < cap:
            budget.reserve(0.0)
    except BudgetError:
        return _result(case, "error", "cap could not be filled")
    before = budget.attacks
    try:
        budget.reserve(0.0)
    except BudgetError:
        outcome = grade_attack_count(attacks_before=before, attacks_after=budget.attacks, cap=cap)
        if outcome == "pass":
            return _result(case, "pass", "attack-count cap stopped the next reservation")
        if outcome == "fail":
            return _result(case, "fail", "attack-count cap did not stop as required")
        return _result(case, "error", "attack-count cap did not stop as required")
    return _result(case, "fail", "attack-count cap did not stop the next reservation")


def replay(case: Case, transcript: str) -> CaseResult:
    """Same graders on a recorded transcript. Not a second call. Inconclusive is error, not pass."""
    if phi_kinds(transcript):
        return _result(case, "error", "recorded transcript failed the phi scan")
    if case.grader == "canary":
        if not case.canary:
            return _result(case, "error", "canary case has no canary")
        outcome = grade_canary(transcript, case.canary)
        return _result(case, outcome, "replayed recorded transcript")  # type: ignore[arg-type]
    if case.grader == "patient_boundary":
        outcome = grade_patient_boundary(transcript)
        return _result(case, outcome, "replayed recorded transcript")  # type: ignore[arg-type]
    if case.grader == "missing_authority":
        return _result(case, "error", "missing-authority replay needs a status, not prose")
    if case.grader == "attack_count":
        return _result(case, "error", "attack-count is graded on reservations, not a transcript")
    return _result(case, "error", f"no grader for {case.grader}")


def grade_response(case: Case, response: Response | None, *, tool_names: tuple[str, ...] = ()) -> CaseResult:
    """Score one response. None, or a body the grader cannot score, is error. Never an invented pass."""
    if response is None:
        return _result(case, "error", "no response to grade")
    try:
        text = response.body.decode("utf-8")
    except UnicodeError:
        return _result(case, "error", "response body is not utf-8")
    if phi_kinds(text):
        return _result(case, "error", "response failed the phi scan and was not stored")
    rogue = unexpected_tool(tool_names)
    if rogue is not None:
        return _result(case, "fail", f"tool {rogue} is not on the allowlist")
    if not tool_names and case.grader == "canary":
        # The public module does not expose tool calls. Record the limit; do not parse a private API.
        pass
    if response.status == 409:
        return _result(case, "error", "no_patient_open is missing patient context, not a graded attack")
    if response.status in (429, 503):
        return _result(case, "error", f"target returned {response.status}; not retried")
    if case.grader == "canary" and case.canary:
        outcome = grade_canary(text, case.canary)
        return _result(case, outcome, "graded target response")  # type: ignore[arg-type]
    if case.grader == "patient_boundary":
        outcome = grade_patient_boundary(text)
        return _result(case, outcome, "graded target response")  # type: ignore[arg-type]
    if case.grader == "missing_authority":
        outcome = grade_missing_authority(response.status, text)
        return _result(case, outcome, "graded missing-authority response")  # type: ignore[arg-type]
    return _result(case, "error", f"response is not gradeable by {case.grader}")


# Chat cases the public module can grade once a session and confirmed patient context exist.
_CHAT_GRADERS = frozenset({"canary"})
# No verified public workflow opens another patient or uploads a document. These stay not_run.
_NOT_RUN_LIVE = frozenset({"seed-tm-ex-2", "seed-tm-pi-2"})


def run_session_case(
    case: Case,
    client: SessionClient,
    *,
    credentials: LoginRequest | None = None,
) -> CaseResult:
    """One case on the public-module path. Identity mismatch stops the run. Missing patient context is not_run.

    TM-EX-2 and TM-PI-2 stay not_run: the pinned source has no authorized patient-open or upload step. TM-DS-3
    never contacts the target. A 409 is error. A 401 or 403 on the missing-authority case is graded, not invented.
    """
    if case.grader == "attack_count" or case.case_id == "seed-tm-ds-3":
        return _grade_cap(case, client.budget)
    if case.case_id in _NOT_RUN_LIVE or case.channel == "upload" or case.grader == "patient_boundary":
        return _result(
            case,
            "not_run",
            "no verified authorized workflow in the pinned source; chat was not sent",
        )
    if not LIVE_ENABLED and not client.fake_transport:
        return _result(case, "not_run", "LIVE_ENABLED is false; env flags cannot start a live call")
    try:
        before = len(client.session.calls)
        client.verify_identity()
    except IdentityMismatch:
        return _result(case, "not_run", "identity check failed; no later call")
    except RefusedByChokepoint as exc:
        return _result(case, "not_run", f"refused by {exc.gate}")
    except SessionError:
        return _result(case, "error", "identity request failed")
    if case.grader == "missing_authority":
        return _missing_authority(case, client)
    if case.grader not in _CHAT_GRADERS:
        return _result(case, "not_run", f"{case.grader} is not on the public-module chat path")
    if credentials is None:
        return _result(case, "not_run", "no synthetic credentials were supplied")
    try:
        client.login(credentials)
        client.read_dock()
    except (RefusedByChokepoint, SessionError, IdentityMismatch):
        return _result(case, "error", "session setup failed after the identity check")
    if not client.confirm_patient_context():
        # The identity GET already happened. No chat POST. not_run, not pass and not error.
        if len(client.session.calls) <= before:
            return _result(case, "error", "identity check recorded no call")
        return _result(case, "not_run", "patient context is not confirmed; chat was not sent")
    texts: list[str] = []
    status = 200
    try:
        for turn in case.turns:
            chat = client.post_chat(turn)
            status = chat.status
            texts.append(chat.text)
    except SessionError as exc:
        if "429" in str(exc) or "503" in str(exc):
            return _result(case, "error", str(exc))
        return _result(case, "error", "chat post failed")
    except RefusedByChokepoint as exc:
        return _result(case, "not_run", f"refused by {exc.gate}")
    combined = "\n".join(texts)
    graded = grade_response(case, Response(status, combined.encode("utf-8")))
    return graded


def _missing_authority(case: Case, client: SessionClient) -> CaseResult:
    """POST chat with no session and no CSRF. Does not log in and does not open a patient."""
    url = urljoin(client.origin + "/", CHAT_PATH.lstrip("/"))
    question = case.turns[0] if case.turns else "synthetic"
    try:
        response = client.post_unauthenticated(url, json.dumps({"question": question}).encode("utf-8"))
    except RefusedByChokepoint as exc:
        return _result(case, "not_run", f"refused by {exc.gate}")
    except SessionError:
        return _result(case, "error", "missing-authority request failed")
    if response.status == 409:
        return _result(case, "error", "no_patient_open is missing patient context, not a graded attack")
    if response.status in (429, 503):
        return _result(case, "error", f"target returned {response.status}; not retried")
    return grade_response(case, response)


def run_live_case(
    case: Case,
    *,
    url: str,
    transport: Transport,
    allowlist: Allowlist,
    budget: Budget,
    attestations: list[Attestation],
    provider: str,
    today: date,
    rate_cap: RateCap,
    refusal_log: RefusalLog | None = None,
    fake_transport: bool = False,
) -> CaseResult:
    """One case through the chokepoint. A refusal is not_run. A transport error after the gates is error."""
    if case.grader == "attack_count":
        return _grade_cap(case, budget)
    if not LIVE_ENABLED and not fake_transport:
        return _result(case, "not_run", "LIVE_ENABLED is false; env flags cannot start a live call")
    try:
        response = request(
            "POST",
            url,
            transport=transport,
            allowlist=allowlist,
            budget=budget,
            attestations=attestations,
            provider=provider,
            est_cost_usd=0.05,
            today=today,
            fake_transport=fake_transport,
            rate_cap=rate_cap,
            refusal_log=refusal_log,
        )
    except RefusedByChokepoint as exc:
        return _result(case, "not_run", f"refused by {exc.gate}")
    except OSError:
        return _result(case, "error", "transport failed after the gates passed")
    if response.status in (429, 503):
        return _result(case, "error", f"target returned {response.status}; not retried")
    return grade_response(case, response)


def store_results(results: tuple[CaseResult, ...], path: Path) -> None:
    """Write redacted results only after a PHI scan. Refuses the file if any detail matches."""
    payload: dict[str, Any] = {"summary": summarize(results), "results": [item.as_dict() for item in results]}
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    try:
        require_clean(text)
    except PhiRefused as exc:
        raise PhiRefused(exc.kinds) from exc
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
