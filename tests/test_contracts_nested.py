"""Nested enforcement. Each of the four failures is planted inside a nested object and inside an array item.

Top-level rejection is not enough. The pinned validator has to walk $ref and items.
"""

from __future__ import annotations

from typing import Any

import pytest

from agentforge.contracts.validate import ContractError, validate

from tests.fixtures import attack_result, confirmed_exploit


def _sequence(message: dict[str, Any]) -> dict[str, Any]:
    sequence: Any = message["input_sequence"] if "input_sequence" in message else message["minimal_sequence"]
    return sequence  # type: ignore[no-any-return]


@pytest.mark.parametrize("builder", [attack_result, confirmed_exploit])
def test_missing_required_field_inside_nested_object(builder: Any) -> None:
    message = builder()
    del _sequence(message)["turns"]
    with pytest.raises(ContractError):
        validate(builder.__name__, message)


@pytest.mark.parametrize("builder", [attack_result, confirmed_exploit])
def test_wrong_type_inside_nested_object(builder: Any) -> None:
    message = builder()
    _sequence(message)["turns"] = "not-an-array"
    with pytest.raises(ContractError):
        validate(builder.__name__, message)


@pytest.mark.parametrize("builder", [attack_result, confirmed_exploit])
def test_bad_enum_inside_nested_object(builder: Any) -> None:
    """The category enum sits on the message. The turn role enum sits one level down, so both depths are checked."""
    message = builder()
    _sequence(message)["channel"] = "fax"
    with pytest.raises(ContractError):
        validate(builder.__name__, message)


@pytest.mark.parametrize("builder", [attack_result, confirmed_exploit])
def test_extra_property_inside_nested_object(builder: Any) -> None:
    message = builder()
    _sequence(message)["note"] = "not in the schema"
    with pytest.raises(ContractError):
        validate(builder.__name__, message)


@pytest.mark.parametrize("builder", [attack_result, confirmed_exploit])
def test_missing_required_field_inside_array_item(builder: Any) -> None:
    message = builder()
    del _sequence(message)["turns"][0]["content"]
    with pytest.raises(ContractError):
        validate(builder.__name__, message)


@pytest.mark.parametrize("builder", [attack_result, confirmed_exploit])
def test_wrong_type_inside_array_item(builder: Any) -> None:
    message = builder()
    _sequence(message)["turns"][0]["content"] = 5
    with pytest.raises(ContractError):
        validate(builder.__name__, message)


@pytest.mark.parametrize("builder", [attack_result, confirmed_exploit])
def test_bad_enum_inside_array_item(builder: Any) -> None:
    message = builder()
    _sequence(message)["turns"][0]["role"] = "system"
    with pytest.raises(ContractError):
        validate(builder.__name__, message)


@pytest.mark.parametrize("builder", [attack_result, confirmed_exploit])
def test_extra_property_inside_array_item(builder: Any) -> None:
    message = builder()
    _sequence(message)["turns"][0]["hidden"] = "no"
    with pytest.raises(ContractError):
        validate(builder.__name__, message)
