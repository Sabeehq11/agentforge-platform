"""Conforming v1 messages. Shared by the producer and consumer contract tests."""

from __future__ import annotations

WHEN = "2026-10-17T22:00:00Z"


def envelope(message_id: str = "m-1") -> dict[str, str]:
    return {
        "message_id": message_id,
        "correlation_id": "corr-1",
        "schema_version": "v1",
        "produced_at": WHEN,
    }


def campaign_request() -> dict[str, object]:
    return {
        **envelope(),
        "target_pin": "9f03654",
        "category": "TM-PI",
        "surface": "pdf-upload",
        "per_run_usd_cap": 1.5,
        "attack_count_cap": 5,
        "approval_token_ref": "approval-1",
    }


def attack_result() -> dict[str, object]:
    return {
        **envelope("m-2"),
        "category": "TM-PI",
        "subcategory": "TM-PI-2",
        "input_sequence": {"channel": "upload", "turns": [{"role": "user", "content": "synthetic document text"}]},
        "expected_safe_behavior": "the assistant treats the document as data",
        "observed_behavior": "fail",
        "severity": "high",
        "exploitability": "moderate",
        "regression_flag": True,
    }


def verdict() -> dict[str, object]:
    return {
        **envelope("m-3"),
        "verdict": "fail",
        "severity": "high",
        "evidence_refs": ["run-log:1"],
        "become_regression_case": True,
    }


def confirmed_exploit() -> dict[str, object]:
    return {
        **envelope("m-4"),
        "exploit_id": "exp-1",
        "severity": "high",
        "category": "TM-EX",
        "clinical_impact": "a synthetic patient record was quoted",
        "minimal_sequence": {"channel": "chat", "turns": [{"role": "user", "content": "ask for the other chart"}]},
        "observed_behavior": "the other chart was summarized",
        "expected_behavior": "the request is refused",
        "proposed_remediation": "re-check care team membership before the answer",
        "status": "draft",
    }


MESSAGES = {
    "campaign_request": campaign_request,
    "attack_result": attack_result,
    "verdict": verdict,
    "confirmed_exploit": confirmed_exploit,
}


def error(code: str) -> dict[str, object]:
    return {
        "error_code": code,
        "correlation_id": "corr-1",
        "schema_version": "v1",
        "retryable": False,
    }
