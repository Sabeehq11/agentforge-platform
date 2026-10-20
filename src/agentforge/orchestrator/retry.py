"""Bounded retry for 429 and 503, and the non-retryable classification. The chokepoint and RateCap stay no-retry.

Every attempt is its own journal row, ledger reservation and RateCap slot. The caller's `make_send(attempt)` builds
the send for that attempt, so identity is re-verified and RateCap.reserve() is called again on every retry. Clock and
sleep are injected. Status and Retry-After are kept verbatim in the journal. A halt uses the existing closed error
codes, with the structured fields in the detail text.

Bounds: at most `max_attempts_per_step` calls in one run_step, and at most `max_attempts_per_campaign` rate-limited
attempts persisted in campaigns.attempt across resumes. A Retry-After above max_delay_s halts without sleeping.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from agentforge.orchestrator.journal import Answered, Journal, NotSent, Outcome, Refused, UnknownOutcome, dispatch
from agentforge.orchestrator.policy import RetryPolicy
from agentforge.orchestrator.state import bump
from agentforge.safety.budget import BudgetError
from agentforge.safety.chokepoint import RefusedByChokepoint
from agentforge.safety.operator_approval import OperatorApprovalRefused
from agentforge.safety.phi import PhiRefused
from agentforge.safety.rate import RateCapExceeded

RETRYABLE_STATUSES = frozenset({429, 503})
BUDGET_GATES = frozenset({"budget", "rate_cap", "ledger"})


@dataclass(frozen=True)
class Halt:
    """A typed halt. code is one of the existing envelope codes."""

    code: str
    retryable: bool
    detail: str
    next_attempt_at: str | None = None


class StepHalt(Exception):
    def __init__(self, halt: Halt) -> None:
        self.halt = halt
        super().__init__(halt.detail)


def is_retryable_status(status: int) -> bool:
    return status in RETRYABLE_STATUSES


def rate_detail(status: int, retry_after_s: float | None) -> str:
    shown = "none" if retry_after_s is None else f"{retry_after_s:g}"
    return f"rate_limited status={status} retry_after_s={shown}"


def backoff_delay(retry_index: int, retry_after_s: float | None, policy: RetryPolicy) -> float:
    """max(Retry-After, base * 2^n), capped at max_delay_s. A malformed Retry-After arrives here as None."""
    return float(min(max(retry_after_s or 0.0, policy.base_delay_s * (2**retry_index)), policy.max_delay_s))


def classify_refusal(exc: Refused) -> Halt:
    """A local gate refused before anything was sent. Never retried."""
    if exc.gate in BUDGET_GATES:
        return Halt("budget_exceeded", False, f"refused {exc.gate}")
    return Halt("target_unreachable", False, f"refused {exc.gate}")


def guard(send: Callable[[], Outcome]) -> Callable[[], Outcome]:
    """Turn a gate exception raised inside send into Refused, so the row is closed and the reservation freed."""

    def guarded() -> Outcome:
        try:
            return send()
        except RefusedByChokepoint as exc:
            raise Refused(exc.gate, exc.reason) from exc
        except PhiRefused as exc:
            raise Refused("phi", str(exc)) from exc
        except OperatorApprovalRefused as exc:
            raise Refused("approval", str(exc)) from exc
        except RateCapExceeded as exc:
            raise Refused("rate_cap", str(exc)) from exc
        except BudgetError as exc:
            raise Refused("budget", str(exc)) from exc

    return guarded


def campaign_attempts(conn: sqlite3.Connection, correlation_id: str) -> int:
    row = conn.execute("SELECT attempt FROM campaigns WHERE correlation_id = ?", (correlation_id,)).fetchone()
    return 0 if row is None else int(row[0])


def _stamp(now: datetime, seconds: float) -> str:
    return (now + timedelta(seconds=seconds)).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _as_answer(send: Callable[[], Outcome]) -> Callable[[], Outcome]:
    """A returned error status is an Answered, so it is stored verbatim and released, never settled as spend."""

    def wrapped() -> Outcome:
        outcome = send()
        if outcome.http_status is not None and outcome.http_status >= 400:
            raise Answered(outcome.http_status, outcome.retry_after_s, f"status {outcome.http_status}")
        return outcome

    return wrapped


def _answer_halt(exc: Answered, policy: RetryPolicy, now: datetime) -> Halt | None:
    """None means retry. A Retry-After above the cap halts retryable with next_attempt_at stored and no sleep."""
    if not is_retryable_status(exc.http_status):
        return Halt("target_unreachable", False, f"non_retryable status={exc.http_status}")
    if exc.retry_after_s is not None and exc.retry_after_s > policy.max_delay_s:
        return Halt(
            "target_unreachable", True, rate_detail(exc.http_status, exc.retry_after_s), _stamp(now, exc.retry_after_s)
        )
    return None


def run_step(
    journal: Journal,
    conn: sqlite3.Connection,
    policy: RetryPolicy,
    correlation_id: str,
    step_no: int,
    *,
    role: str,
    kind: str,
    intent: str,
    reserve_usd: float,
    make_send: Callable[[int], Callable[[], Outcome]],
    sleep: Callable[[float], None],
    clock: Callable[[], datetime] | None = None,
    sequence_id: str | None = None,
    extra_sql: tuple[str, tuple[Any, ...]] | None = None,
) -> Outcome:
    """Dispatch one step with bounded backoff. Returns the outcome, or raises StepHalt with the typed halt.

    An unknown outcome is not a rate limit: UnknownOutcome propagates and is never retried.
    """
    now_of = clock or (lambda: datetime.now(timezone.utc))
    tries = 0
    while True:
        if tries >= policy.max_attempts_per_step:
            raise StepHalt(Halt("target_unreachable", True, "rate_limited step attempt bound reached"))
        if campaign_attempts(conn, correlation_id) >= policy.max_attempts_per_campaign:
            raise StepHalt(Halt("target_unreachable", True, "rate_limited campaign attempt bound reached"))
        attempt = journal.next_attempt(correlation_id, step_no)
        try:
            return dispatch(
                journal, correlation_id, step_no, attempt, role=role, kind=kind, intent=intent,
                reserve_usd=reserve_usd, send=_as_answer(guard(make_send(attempt))), sequence_id=sequence_id,
                extra_sql=extra_sql if attempt == 0 else None,
            )
        except Refused as exc:
            raise StepHalt(classify_refusal(exc)) from exc
        except (BudgetError, RateCapExceeded) as exc:
            raise StepHalt(Halt("budget_exceeded", False, f"refused reserve: {type(exc).__name__}")) from exc
        except UnknownOutcome:
            raise
        except NotSent:
            halt = None
            status, retry_after = None, None
        except Answered as exc:
            halt = _answer_halt(exc, policy, now_of())
            status, retry_after = exc.http_status, exc.retry_after_s
            if halt is not None:
                raise StepHalt(halt) from exc
        bump(conn, correlation_id, "attempt")
        tries += 1
        if tries >= policy.max_attempts_per_step or campaign_attempts(conn, correlation_id) >= policy.max_attempts_per_campaign:
            detail = rate_detail(status, retry_after) if status is not None else "connection error before send"
            raise StepHalt(Halt("target_unreachable", True, detail))
        sleep(backoff_delay(tries - 1, retry_after, policy))
