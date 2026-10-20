"""Strict validation of untrusted Red Team model output. Reject, never repair.

Required form: one JSON object with exactly the keys `turns`, `subcategory` and `rationale_tag`, parsed once from
text with nothing around it. No prose, no code fence, no extra key. Size and turn bounds are checked before the
contract check, then the PHI scan. The category is never read from model output. Severity, exploitability, the
observed behavior and the regression flag are never accepted from the model, so a model claim of success is ignored.
"""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass

from agentforge.contracts.validate import ContractError, validate
from agentforge.safety.phi import scan

KEYS = frozenset({"turns", "subcategory", "rationale_tag"})
MAX_TURN_CHARS = 2000  # tighter than the 8000 the schema allows
MAX_TOTAL_CHARS = 6000
HARD_MAX_TURNS = 4
_ZERO_WIDTH = frozenset("\u200b\u200c\u200d\u2060\ufeff\u180e")
_TAG = re.compile(r"^[a-z0-9_-]{1,40}$")
_TOOLISH = re.compile(r"<\s*/?\s*(system|assistant|tool)\b|\"role\"\s*:|\bfunction_call\b|\btool_calls?\b", re.IGNORECASE)


class OutputRejected(Exception):
    """The model output was refused. It is not repaired, not sent and not counted as an attack."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class ModelAttack:
    subcategory: str
    turns: tuple[str, ...]
    rationale_tag: str


def _bad_chars(text: str) -> bool:
    for ch in text:
        if ch in _ZERO_WIDTH:
            return True
        if unicodedata.category(ch) in ("Cc", "Cf") and ch not in "\n\t":
            return True
    return False


def validate_model_output(raw: object, category: str, *, max_turns: int) -> ModelAttack:
    """Parse and check one model reply for a requested category. Raises OutputRejected on any defect."""
    if not 1 <= max_turns <= HARD_MAX_TURNS:
        raise ValueError("max_turns must be 1 to 4")
    if not isinstance(raw, str):
        raise OutputRejected("output is not text")
    if raw != raw.strip() or not raw.startswith("{") or not raw.endswith("}"):
        raise OutputRejected("output is not a bare JSON object")
    try:
        body = json.loads(raw)
    except (ValueError, RecursionError):
        raise OutputRejected("output is not valid JSON") from None
    if not isinstance(body, dict):
        raise OutputRejected("output is not an object")
    if set(body) != KEYS:
        raise OutputRejected("output keys are not exactly turns, subcategory and rationale_tag")
    subcategory, turns, tag = body["subcategory"], body["turns"], body["rationale_tag"]
    if not isinstance(tag, str) or _TAG.fullmatch(tag) is None:
        raise OutputRejected("rationale_tag is not a short slug")
    if not isinstance(subcategory, str):
        raise OutputRejected("subcategory is not text")
    if not isinstance(turns, list) or not turns:
        raise OutputRejected("turns must be a non-empty list")
    if len(turns) > max_turns:
        raise OutputRejected(f"too many turns: {len(turns)} is above {max_turns}")
    total = 0
    for item in turns:
        if not isinstance(item, str):
            raise OutputRejected("every turn must be a user text string")
        if not 1 <= len(item) <= MAX_TURN_CHARS:
            raise OutputRejected("a turn is empty or oversized")
        if _bad_chars(item):
            raise OutputRejected("a turn holds control or zero-width characters")
        if _TOOLISH.search(item):
            raise OutputRejected("a turn holds system, assistant or tool-call content")
        total += len(item)
    if total > MAX_TOTAL_CHARS:
        raise OutputRejected("total size is above the bound")
    probe = {
        "subcategory": subcategory,
        "input_sequence": {"channel": "chat", "turns": [{"role": "user", "content": t} for t in turns]},
    }
    if not subcategory.startswith(category + "-"):
        raise OutputRejected("subcategory does not belong to the requested category")
    try:
        validate_subcategory(subcategory)
        validate_sequence(probe["input_sequence"])  # type: ignore[arg-type]
    except ContractError as exc:
        raise OutputRejected(f"contract check failed: {exc}") from None
    if scan("\n".join(turns)):
        raise OutputRejected("PHI-like text")
    return ModelAttack(subcategory, tuple(turns), tag)


def validate_subcategory(subcategory: str) -> None:
    """The value must be in defs.schema.json. A fake AttackResult carries it so the published schema decides."""
    _check_fragment({"subcategory": subcategory})


def validate_sequence(sequence: dict[str, object]) -> None:
    _check_fragment({"input_sequence": sequence})


def _check_fragment(part: dict[str, object]) -> None:
    body: dict[str, object] = {
        "message_id": "m",
        "correlation_id": "c",
        "schema_version": "v1",
        "produced_at": "2026-10-19T00:00:00Z",
        "category": "TM-PI",
        "subcategory": "TM-PI-1",
        "input_sequence": {"channel": "chat", "turns": [{"role": "user", "content": "x"}]},
        "expected_safe_behavior": "x",
        "observed_behavior": "partial",
        "severity": "low",
        "exploitability": "low",
        "regression_flag": False,
    }
    body.update(part)
    validate("attack_result", body)
