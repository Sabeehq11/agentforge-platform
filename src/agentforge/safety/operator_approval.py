"""Operator approval for a local $5 testing budget. This is not a provider-dashboard attestation.

The file records that an operator approved a scoped spend ceiling. It does not claim a provider limit
exists, and this module never writes config/spend_limits.yaml.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import yaml

from agentforge.safety.spend_limits import Attestation, SpendLimitNotAttested, require_attested

APPROVED_USD = 5.0
SCOPES = frozenset({"local-target", "openrouter"})
_SCOPE_PROVIDER = {"local-target": "target", "openrouter": "openrouter"}


class OperatorApprovalRefused(Exception):
    pass


@dataclass(frozen=True)
class OperatorApproval:
    approved_by: str
    approved_on: date
    scope: str
    max_usd: float
    purpose: str


def load_approvals(path: str | Path) -> list[OperatorApproval]:
    """A missing or malformed file yields no approvals, so billable use stays refused."""
    try:
        data: Any = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return []
    if not isinstance(data, dict) or not isinstance(data.get("approvals"), list):
        return []
    out: list[OperatorApproval] = []
    for raw in data["approvals"]:
        try:
            on = raw["approved_on"]
            if not isinstance(on, date):
                on = date.fromisoformat(str(on))
            scope = str(raw["scope"])
            if scope not in SCOPES:
                continue
            out.append(
                OperatorApproval(
                    approved_by=str(raw["approved_by"]).strip(),
                    approved_on=on,
                    scope=scope,
                    max_usd=float(raw["max_usd"]),
                    purpose=str(raw["purpose"]).strip(),
                )
            )
        except (KeyError, TypeError, ValueError):
            continue
    return out


def require_operator_approval(
    scope: str,
    approvals: list[OperatorApproval],
    *,
    today: date,
    max_age_days: int = 7,
) -> OperatorApproval:
    """Return a fresh $5 approval for this scope or raise. A $6 or stale record never matches."""
    if scope not in SCOPES:
        raise OperatorApprovalRefused(f"unknown operator-approval scope {scope!r}")
    for item in approvals:
        if item.scope != scope or not item.approved_by or not item.purpose:
            continue
        if item.max_usd != APPROVED_USD:
            continue
        age = today - item.approved_on
        if timedelta(0) <= age <= timedelta(days=max_age_days):
            return item
    raise OperatorApprovalRefused(f"no fresh operator approval for {scope!r}")


def authorize_spend(
    provider: str,
    *,
    attestations: list[Attestation],
    approvals: list[OperatorApproval],
    today: date,
) -> str:
    """Accept a dashboard attestation or a matching operator approval. Never writes either file."""
    try:
        require_attested(provider, attestations, today=today)
        return "attestation"
    except SpendLimitNotAttested as attested:
        scope = next((name for name, mapped in _SCOPE_PROVIDER.items() if mapped == provider.lower()), "")
        if not scope:
            raise SpendLimitNotAttested(f"no operator-approval scope for {provider!r}") from attested
        try:
            require_operator_approval(scope, approvals, today=today)
        except OperatorApprovalRefused as exc:
            raise SpendLimitNotAttested(str(exc)) from exc
        return "operator_approval"
