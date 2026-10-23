"""Validate human-supplied provider-cap evidence (plan section 5, R8 Level 3).

The provider cap is UNVERIFIED today. This module cannot verify any dashboard setting and calls no provider. It
only judges a record that a named human wrote from the dashboard or from a written owner statement. A valid record
is an attestation that a human saw a limit. It is not a platform-verified limit, and even a verified limit on the
shared key protects the account, not this platform's budget.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

from agentforge.gates.ceiling import CEILING_USD, load_exposure
from agentforge.gates.common import (
    is_blank,
    load_mapping,
    parse_date,
    secret_problems,
    to_decimal,
)

STATUS = "attested_not_verified"
METHODS = frozenset({"dashboard", "owner_statement"})
MAX_AGE_DAYS = 30  # the same freshness window as src/agentforge/safety/spend_limits.py

ACCEPTED = "accepted"
BLOCKED = "blocked"
BLOCKED_DEVIATION = "blocked_deviation_accepted"


@dataclass(frozen=True)
class EvidenceResult:
    problems: tuple[str, ...]

    @property
    def valid(self) -> bool:
        return not self.problems


def validate_evidence(record: dict[str, Any] | None, *, today: date) -> EvidenceResult:
    """Every problem found. A missing record and an unfilled template both fail."""
    if record is None:
        return EvidenceResult(("provider-cap evidence is missing or unreadable",))
    problems: list[str] = list(secret_problems(record, "provider-cap evidence"))

    if record.get("status") != STATUS:
        problems.append(
            f"status must be exactly {STATUS!r}: a human attestation, not a verified limit"
        )
    if record.get("provider") != "openrouter":
        problems.append("provider must be 'openrouter'")
    for key in ("key_label", "observed_by", "reference"):
        if is_blank(record.get(key)):
            problems.append(f"{key} is missing")
    if record.get("method") not in METHODS:
        problems.append("method must be 'dashboard' or 'owner_statement'")
    if record.get("per_key_limit") is not True:
        problems.append(
            "per_key_limit must be true: a limit on this key, not only on the account"
        )

    limit = to_decimal(record.get("limit_usd"))
    usage = to_decimal(record.get("usage_usd"))
    if limit is None or limit <= 0:
        problems.append("limit_usd must be a positive amount")
    if usage is None:
        problems.append("usage_usd must be a non-negative amount")
    if limit is not None and usage is not None and limit > 0 and usage >= limit:
        problems.append(
            "the key is already at or over its limit (usage_usd >= limit_usd)"
        )
    if record.get("limit_exceeded_already") is not False:
        problems.append("limit_exceeded_already must be false")

    observed = parse_date(record.get("observed_on"))
    if observed is None:
        problems.append("observed_on must be an ISO date")
    elif observed > today:
        problems.append("observed_on is in the future")
    elif (today - observed).days > MAX_AGE_DAYS:
        problems.append(f"observed_on is older than {MAX_AGE_DAYS} days")

    return EvidenceResult(tuple(problems))


def validate_deviation(record: dict[str, Any] | None, *, today: date) -> EvidenceResult:
    """A written, in-repo-caps-only deviation. It records a decision. It does not close E-6 or accept R8."""
    if record is None:
        return EvidenceResult(("deviation record is missing or unreadable",))
    problems: list[str] = list(secret_problems(record, "deviation"))
    if record.get("scope") != "in-repo-caps-only":
        problems.append("scope must be exactly 'in-repo-caps-only'")
    for key in ("approved_by", "statement"):
        if is_blank(record.get(key)):
            problems.append(f"{key} is missing")
    approved = parse_date(record.get("approved_on"))
    if approved is None:
        problems.append("approved_on must be an ISO date")
    elif approved > today:
        problems.append("approved_on is in the future")
    return EvidenceResult(tuple(problems))


def local_caps_problem(root: Path, *, today: date) -> str | None:
    """Why a deviation cannot replace a provider attestation, or None when the local caps hold.

    The record alone is not enough. The $5 caps, the shared ledger ceiling, reservation refusal, both
    default-off switches, and a current $12 reconciliation must all be present. This does not close E-6 or R8.
    """
    deviation = validate_deviation(
        load_mapping(root / "Docs/attestations/provider-cap-deviation.yaml"), today=today
    )
    if not deviation.valid:
        return "no valid in-repo-caps-only deviation"
    budget = load_mapping(root / "config/budget.yaml")
    if budget is None or budget.get("per_run_usd") != 5 or budget.get("per_day_usd") != 5:
        return "the $5 per-run and per-day caps are not configured"
    ceilings = (budget.get("hard_ceiling_per_run_usd"), budget.get("hard_ceiling_per_day_usd"))
    if any(not isinstance(value, (int, float)) or float(value) < 5 for value in ceilings):
        return "a hard ceiling is below the $5 cap"
    try:
        ledger = (root / "src/agentforge/safety/ledger.py").read_text(encoding="utf-8")
        budget_source = (root / "src/agentforge/safety/budget.py").read_text(encoding="utf-8")
        switches = (root / "src/agentforge/safety/chokepoint.py").read_text(encoding="utf-8")
    except OSError:
        return "local cap enforcement is unreadable"
    if "SHARED_CEILING_USD = 5.0" not in ledger or "committed_usd" not in ledger:
        return "the shared $5 ledger ceiling is not enforced"
    if "BudgetExceeded" not in budget_source or "def reserve" not in budget_source:
        return "the budget reserve refusal is not enforced"
    if not re.search(r"^LIVE_ENABLED = False$", switches, re.MULTILINE) or not re.search(
        r"^PROVIDER_ENABLED = False$", switches, re.MULTILINE
    ):
        return "a live switch is not default-off"
    exposure, _problems = load_exposure(root / "Docs/attestations/spend-reconciliation.yaml", today=today)
    if exposure is None or exposure.total > CEILING_USD:
        return "the $12 lifetime ceiling is not currently satisfied"
    return None


def r8_status(
    *, evidence_valid: bool, attestation_committed: bool, deviation_valid: bool
) -> str:
    """R8 is accepted only with valid evidence and the committed attestation. A deviation never accepts it."""
    if evidence_valid and attestation_committed:
        return ACCEPTED
    if deviation_valid:
        return BLOCKED_DEVIATION
    return BLOCKED


def load_evidence(path: Path, *, today: date) -> EvidenceResult:
    return validate_evidence(load_mapping(path), today=today)
