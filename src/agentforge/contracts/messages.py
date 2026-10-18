"""Typed shapes for the v1 messages. A TypedDict is not a check. Call validate() before trusting one.

Field names match contracts/v1. Category values are the threat-model ids.
"""

from __future__ import annotations

from typing import Literal, TypedDict

Category = Literal["TM-PI", "TM-EX", "TM-SC", "TM-TM", "TM-DS", "TM-ID"]
Severity = Literal["critical", "high", "medium", "low"]
Observed = Literal["pass", "fail", "partial"]
ErrorCode = Literal[
    "target_unreachable",
    "budget_exceeded",
    "judge_timeout",
    "no_findings_in_window",
    "regression_detected",
]


class Turn(TypedDict):
    role: Literal["user", "target"]
    content: str


class InputSequence(TypedDict):
    channel: Literal["chat", "upload"]
    turns: list[Turn]


class CampaignRequest(TypedDict):
    """Orchestrator to Red Team. A campaign order. No attack payload."""

    message_id: str
    correlation_id: str
    schema_version: Literal["v1"]
    produced_at: str
    target_pin: str
    category: Category
    surface: str
    per_run_usd_cap: float
    attack_count_cap: int
    approval_token_ref: str


class AttackResult(TypedDict):
    """Red Team to Judge."""

    message_id: str
    correlation_id: str
    schema_version: Literal["v1"]
    produced_at: str
    category: Category
    subcategory: str
    input_sequence: InputSequence
    expected_safe_behavior: str
    observed_behavior: Observed
    severity: Severity
    exploitability: Literal["low", "moderate", "high"]
    regression_flag: bool


class Verdict(TypedDict):
    """Judge to regression harness. No attacker claim of success.

    needs_human_review is an optional schema field. It is not a required key here, because the contract
    test equates TypedDict keys with required schema fields. A timeout is not a verdict and does not use it.
    """

    message_id: str
    correlation_id: str
    schema_version: Literal["v1"]
    produced_at: str
    verdict: Observed
    severity: Severity
    evidence_refs: list[str]
    become_regression_case: bool


class ConfirmedExploit(TypedDict):
    """Judge to Documentation. Status is draft. An agent cannot publish."""

    message_id: str
    correlation_id: str
    schema_version: Literal["v1"]
    produced_at: str
    exploit_id: str
    severity: Severity
    category: Category
    clinical_impact: str
    minimal_sequence: InputSequence
    observed_behavior: str
    expected_behavior: str
    proposed_remediation: str
    status: Literal["draft"]


class ErrorEnvelope(TypedDict, total=False):
    error_code: ErrorCode
    correlation_id: str
    schema_version: Literal["v1"]
    retryable: bool
    detail: str
