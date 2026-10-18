"""Protocols each later agent must satisfy. No method here runs, calls a model, or writes the store.

Return types name the published message or the published error. A caller validates either with
agentforge.contracts.validate before acting on it.
"""

from __future__ import annotations

from typing import Protocol

from agentforge.contracts.messages import (
    AttackResult,
    CampaignRequest,
    ConfirmedExploit,
    ErrorEnvelope,
    Verdict,
)


class RedTeam(Protocol):
    """Accepts a campaign order. Returns an attack result, or a budget or reachability error."""

    def propose(self, request: CampaignRequest) -> AttackResult | ErrorEnvelope:
        """BudgetExceeded and TargetUnreachable are the errors this role may return."""


class Judge(Protocol):
    """Independent of attack generation. Sees the result, not the attacker's claim of success."""

    def judge(self, result: AttackResult) -> Verdict | ConfirmedExploit | ErrorEnvelope:
        """JudgeTimeout and NoFindingsInWindow are the errors this role may return."""


class Documentation(Protocol):
    """Turns a confirmed exploit into a draft. Does not publish."""

    def draft(self, exploit: ConfirmedExploit) -> str:
        """Returns a draft-report id. Publication is a human act and is not a method here."""


class Harness(Protocol):
    """Accepts a verdict. Does not run the suite. The runner is P7."""

    def accept(self, verdict: Verdict) -> ErrorEnvelope | None:
        """Returns RegressionDetected, or None when the verdict adds no regression signal."""


class Orchestrator(Protocol):
    """Emits the next campaign order from coverage and open findings. Does not run the campaign."""

    def next_request(self, correlation_id: str) -> CampaignRequest | None:
        """None means no priority. The fallback that handles that case is P6, not this protocol."""
