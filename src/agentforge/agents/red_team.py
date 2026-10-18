"""Minimal Red Team. Mutates one existing seed under the budget. Does not call a model or open a socket.

This is the P4 seed, not the P6 generator. It does not invent a novel attack, score novelty, or run a search.
A refused reserve returns budget_exceeded and emits no AttackResult.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from agentforge.contracts.messages import AttackResult, CampaignRequest, ErrorEnvelope
from agentforge.contracts.validate import ContractError, validate
from agentforge.evals.cases import Case
from agentforge.safety.budget import BudgetError
from agentforge.safety.ledger import Ledger


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _budget_error(correlation_id: str, detail: str) -> ErrorEnvelope:
    body: ErrorEnvelope = {
        "error_code": "budget_exceeded",
        "correlation_id": correlation_id,
        "schema_version": "v1",
        "retryable": False,
        "detail": detail[:500],
    }
    validate("budget_exceeded", body)
    return body


def mutate_seed(seed: Case) -> tuple[str, ...]:
    """Bounded mutations of the first turn: a suffix, a trailing space, and that turn copied once.

    The extra turn is copied from the seed. It is not a new attack idea.
    """
    if not seed.turns:
        raise ValueError("seed has no turn to mutate")
    first = seed.turns[0]
    return (first + " [mutated-suffix]", first + " ", first)


class SeedMutator:
    """propose() reserves one attack, then returns an AttackResult. A kill or cap stops before that."""

    def __init__(self, ledger: Ledger, seeds: dict[str, Case], *, reserve_usd: float = 0.0) -> None:
        self._ledger = ledger
        self._seeds = seeds
        self._reserve_usd = reserve_usd
        self.mutations = 0

    def propose(self, request: CampaignRequest) -> AttackResult | ErrorEnvelope:
        validate("campaign_request", request)
        seed = self._seeds.get(request["category"])
        if seed is None:
            return _budget_error(request["correlation_id"], "no seed for the requested category")
        call_id = f"red-{request['correlation_id']}-{self.mutations}"
        try:
            self._ledger.reserve(call_id, "red_team", self._reserve_usd)
        except BudgetError as exc:
            return _budget_error(request["correlation_id"], str(exc))
        turns = mutate_seed(seed)
        self.mutations += 1
        body: AttackResult = {
            "message_id": uuid4().hex[:16],
            "correlation_id": request["correlation_id"],
            "schema_version": "v1",
            "produced_at": _now(),
            "category": seed.category,  # type: ignore[typeddict-item]
            "subcategory": seed.subcategory,
            "input_sequence": {
                "channel": seed.channel,  # type: ignore[typeddict-item]
                "turns": [{"role": "user", "content": turn} for turn in turns],
            },
            "expected_safe_behavior": seed.expected_safe_behavior,
            "observed_behavior": "partial",
            "severity": seed.severity,  # type: ignore[typeddict-item]
            "exploitability": seed.exploitability,  # type: ignore[typeddict-item]
            "regression_flag": False,
        }
        try:
            validate("attack_result", body)
        except ContractError:
            self._ledger.release(call_id)
            self.mutations -= 1
            raise
        self._ledger.incur(call_id, self._reserve_usd)
        return body
