"""Spend and destination guard for one isolated LLM01 synthesis probe.

This file does not call a provider. A caller hands it a request body and a mocked or live response. It refuses a
request before that request is written when the destination, prompt size, output cap, call count, or remaining
spend would break the bound. It does not import the pinned target and it does not open a socket.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

MAX_INPUT_TOKENS = 1000
MAX_OUTPUT_TOKENS = 300
MAX_CALLS = 2
CEILING_USD = 0.015
PROMPT_USD_PER_TOKEN = 0.000003
COMPLETION_USD_PER_TOKEN = 0.000015
WORST_CALL_USD = MAX_INPUT_TOKENS * PROMPT_USD_PER_TOKEN + MAX_OUTPUT_TOKENS * COMPLETION_USD_PER_TOKEN
ALLOWED_HOST = "openrouter.ai"
ALLOWED_PATH = "/api/v1/chat/completions"


class GuardRefused(Exception):
    """A local refusal. No provider request was written."""


def _worst(reported: float | None) -> float:
    return WORST_CALL_USD if reported is None else reported


def estimate_input_tokens(body: dict[str, Any]) -> int:
    """A conservative count: characters divided by 3, rounded up. It never underestimates the cap check."""
    messages = body.get("messages")
    if not isinstance(messages, list):
        raise GuardRefused("messages missing")
    chars = len(json.dumps(messages, ensure_ascii=False, separators=(",", ":")))
    return (chars + 2) // 3


@dataclass
class SynthesisGuard:
    """Two capped calls, one host, and a $0.015 ceiling. A missing reported cost counts as the worst capped call."""

    calls: int = 0
    spent_usd: float = 0.0
    overrun: bool = False

    def check(self, url: str, body: dict[str, Any]) -> None:
        parts = urlsplit(url)
        if parts.scheme != "https" or parts.hostname != ALLOWED_HOST or parts.path != ALLOWED_PATH:
            raise GuardRefused("destination is not the provider")
        if parts.username or parts.password or parts.port not in (None, 443):
            raise GuardRefused("destination is not the provider")
        if self.overrun:
            raise GuardRefused("prior call overran the cap")
        if self.calls >= MAX_CALLS:
            raise GuardRefused("call count exceeded")
        estimate = estimate_input_tokens(body)
        if estimate > MAX_INPUT_TOKENS:
            raise GuardRefused("input token estimate exceeded")
        if body.get("max_tokens") != MAX_OUTPUT_TOKENS:
            raise GuardRefused("output token cap missing")
        if body.get("tools"):
            raise GuardRefused("tools are not allowed")
        if self.spent_usd + WORST_CALL_USD > CEILING_USD + 1e-12:
            raise GuardRefused("ceiling would be exceeded")

    def record(self, *, prompt_tokens: int | None, completion_tokens: int | None, cost_usd: float | None) -> None:
        """Record one response. A missing cost counts as $0.0075. An overrun blocks the retry."""
        self.calls += 1
        reported = _worst(cost_usd)
        self.spent_usd += reported
        if (
            (prompt_tokens or 0) > MAX_INPUT_TOKENS
            or (completion_tokens or 0) > MAX_OUTPUT_TOKENS
            or reported > WORST_CALL_USD
            or self.spent_usd > CEILING_USD + 1e-12
        ):
            self.overrun = True


def prepare_body(body: dict[str, Any]) -> dict[str, Any]:
    """Return a copy with the output cap set. The original body is not changed."""
    prepared = dict(body)
    prepared["max_tokens"] = MAX_OUTPUT_TOKENS
    prepared.pop("tools", None)
    return prepared
