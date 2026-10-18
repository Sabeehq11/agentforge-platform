"""Producer-side and consumer-side contract tests for the four v1 messages and the five errors.

Both sides validate the same bytes against the published schema. Neither imports the other's builder, which is the
stand-in for a peer that has the schema and not the source (ROADMAP section 4, peer versus stub).
"""

from __future__ import annotations

import copy
import importlib
from typing import Any

import pytest

from agentforge.contracts.messages import AttackResult, CampaignRequest, ConfirmedExploit, Verdict
from agentforge.contracts.validate import ERRORS, ContractError, validate

from tests.fixtures import MESSAGES, error

TYPED: dict[str, type] = {
    "campaign_request": CampaignRequest,
    "attack_result": AttackResult,
    "verdict": Verdict,
    "confirmed_exploit": ConfirmedExploit,
}


def _producer(name: str) -> dict[str, Any]:
    """A producer knows the field names and builds the message. It does not import the consumer."""
    return MESSAGES[name]()


def _consumer(name: str, payload: dict[str, Any]) -> None:
    """A consumer knows only the schema. It validates and reads one required field."""
    validate(name, payload)
    assert payload["schema_version"] == "v1"


@pytest.mark.parametrize("name", sorted(MESSAGES))
def test_producer_and_consumer_accept_the_same_message(name: str) -> None:
    payload = _producer(name)
    validate(name, payload)
    _consumer(name, copy.deepcopy(payload))


@pytest.mark.parametrize("name", sorted(MESSAGES))
def test_both_sides_reject_a_forbidden_field(name: str) -> None:
    payload = _producer(name)
    payload["attacker_claim"] = "succeeded"
    with pytest.raises(ContractError):
        validate(name, payload)
    with pytest.raises(ContractError):
        _consumer(name, payload)


@pytest.mark.parametrize("name", sorted(MESSAGES))
def test_typed_dict_keys_match_the_schema(name: str) -> None:
    annotations = TYPED[name].__annotations__
    assert set(annotations) == set(_producer(name))


@pytest.mark.parametrize("code", ERRORS)
def test_each_error_validates_against_its_own_schema(code: str) -> None:
    validate(code, error(code))


@pytest.mark.parametrize("code", ERRORS)
def test_unknown_error_code_is_rejected(code: str) -> None:
    payload = error(code)
    payload["error_code"] = "kill_switch"
    with pytest.raises(ContractError):
        validate(code, payload)


def test_confirmed_exploit_cannot_say_published() -> None:
    payload = _producer("confirmed_exploit")
    payload["status"] = "published"
    with pytest.raises(ContractError):
        validate("confirmed_exploit", payload)


def test_an_unknown_schema_is_rejected() -> None:
    with pytest.raises(ContractError, match="unknown schema"):
        validate("not_a_message", {})


def test_a_bad_date_is_rejected() -> None:
    payload = _producer("campaign_request")
    payload["produced_at"] = "yesterday"
    with pytest.raises(ContractError):
        validate("campaign_request", payload)


def test_consumer_module_does_not_import_the_producer_builder() -> None:
    """The two sides share the schema, not a builder. The consumer module is the validator."""
    consumer = importlib.import_module("agentforge.contracts.validate")
    assert not hasattr(consumer, "campaign_request")
