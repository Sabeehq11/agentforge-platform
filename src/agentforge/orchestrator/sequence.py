"""Executor for one attack sequence. Not an agent: it sends turns and records what the target said.

Every request goes through SessionClient, so through the chokepoint, RateCap and Budget. Setup (identity, login,
dock, patient open) is one journaled step and each chat turn is its own journaled step. The preflight is
all-or-nothing and runs before the first request.

sequences_started is bumped in the same transaction as the setup row's `intended` insert, and turns_sent in the same
transaction as each turn's `intended` insert. Step numbers come from the sequence number, so a resume cannot reuse
one or count twice. A turn that ends `unknown` stays counted. A turn never inserted is never counted.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from agentforge.evals.login import LoginRequest
from agentforge.evals.session import SendFact, SessionClient, SessionError, TargetStatusError
from agentforge.orchestrator.journal import Journal, Outcome, Refused, parse_retry_after
from agentforge.orchestrator.policy import Config
from agentforge.orchestrator.retry import Halt, StepHalt, run_step
from agentforge.orchestrator.state import require_campaign
from agentforge.safety.chokepoint import RefusedByChokepoint
from agentforge.safety.identity import IdentityMismatch
from agentforge.safety.ledger import SHARED_CEILING_USD, committed_usd

SETUP_REQUESTS = 6  # identity, login, landing, dock, demographics, read-back: an upper bound
STEPS_PER_SEQUENCE = 10  # step 0 is setup, steps 1..4 are turns (max_turns hard ceiling is 4)


class PreflightRefused(Exception):
    """The whole sequence is refused before any request. Nothing is sent and no counter changes."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass
class SequenceResult:
    sequence_id: str
    turns_sent: int = 0
    texts: list[str] = field(default_factory=list)
    status: int | None = None
    halt: Halt | None = None
    transcript: dict[str, Any] | None = None
    unrecordable: bool = False  # a turn completed before a crash. It is not re-sent and its text is gone.
    # Send-time facts for this sequence only, sliced from the client log. A resumed sequence has facts for the
    # requests sent after the resume, so it cannot be verified as a whole and says so.
    facts: list[SendFact] = field(default_factory=list)
    resumed: bool = False


def sequence_cap(request_cap: int, config: Config) -> int:
    """The lower of the request value and max_sequences_per_campaign. A larger request value is clamped, never raised."""
    return max(0, min(int(request_cap), config.limits.max_sequences_per_campaign))


def preflight(
    conn: sqlite3.Connection,
    correlation_id: str,
    turns: int,
    config: Config,
    client: SessionClient,
    *,
    chat_reserve_usd: float,
    request_cap: int,
) -> None:
    """All-or-nothing. Raises PreflightRefused before any request, with no counter changed."""
    campaign = require_campaign(conn, correlation_id)
    if int(campaign["sequences_started"]) + 1 > sequence_cap(request_cap, config):
        raise PreflightRefused("sequence cap would be exceeded")
    if int(campaign["turns_sent"]) + turns > config.max_turns_total:
        raise PreflightRefused("turn cap would be exceeded")
    if turns < 1 or turns > config.limits.max_turns:
        raise PreflightRefused("turn count is outside the per-sequence bound")
    cap = client.rate_cap
    if cap.used + SETUP_REQUESTS + turns > cap.max_requests:
        raise PreflightRefused("request-rate headroom is below setup plus every turn")
    budget = client.budget
    # Setup requests count as attacks in the chokepoint, and each journaled target step (setup plus every turn) counts
    # one more through the ledger reservation. The chat POST itself reaches the chokepoint with attack=False.
    if budget.attacks + SETUP_REQUESTS + 1 + turns > budget.caps.max_attacks_per_run:
        raise PreflightRefused("attack-count headroom is below the setup requests")
    need = turns * chat_reserve_usd  # the chokepoint reserves each chat estimate in Budget too, so Budget sees it twice
    if committed_usd(conn) + need > SHARED_CEILING_USD or budget.run_spent + 2 * need > budget.caps.per_run_usd:
        raise PreflightRefused("ledger headroom is below every chat reservation")


def sequence_id_for(correlation_id: str, number: int) -> str:
    return f"seq-{correlation_id}-{number}"


SEQUENCE_STEP_BASE = 1000  # steps below this belong to the loop (model calls and judging)


def _typed(exc: Exception) -> Exception:
    """Map a session failure to the journal's typed exceptions. A transport failure after the gates is unknown."""
    from agentforge.orchestrator.journal import Answered

    if isinstance(exc, TargetStatusError):
        return Answered(exc.status, parse_retry_after(exc.retry_after), f"status {exc.status}")
    if isinstance(exc, IdentityMismatch):
        return Refused("identity_mismatch", exc.reason)
    if isinstance(exc, SessionError) and str(exc).startswith("transport failed"):
        return OSError("transport failed after the gates passed")
    return Refused("session", str(exc)[:200])


class SequenceRunner:
    """Runs one sequence at a time on an identity-checked session. Records the transcript as the executor."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        journal: Journal,
        config: Config,
        client: SessionClient,
        credentials: LoginRequest | None,
        fixture_pid: str,
        *,
        sleep: Callable[[float], None],
        chat_reserve_usd: float = 0.05,
        request_cap: int = 5,
    ) -> None:
        self._conn = conn
        self._journal = journal
        self._config = config
        self._client = client
        self._credentials = credentials
        self._pid = fixture_pid
        self._sleep = sleep
        self._chat_reserve = chat_reserve_usd
        self._request_cap = request_cap
        self.identity_calls = 0

    def _setup_send(self, _attempt: int) -> Callable[[], Outcome]:
        def send() -> Outcome:
            try:
                self.identity_calls += 1
                self._client.verify_identity()  # the first target call, and again on every retry
                self._client.login(self._credentials)
                self._client.read_dock()
                self._client.open_patient(self._pid)
            except RefusedByChokepoint:
                raise
            except Exception as exc:
                raise _typed(exc) from exc
            return Outcome(output="setup-ok", incurred_usd=0.0, http_status=200)

        return send

    def _turn_send(self, turn: str, attempt: int, box: dict[str, Any]) -> Callable[[], Outcome]:
        def send() -> Outcome:
            try:
                if attempt > 0:
                    self.identity_calls += 1
                    self._client.verify_identity()  # identity is re-checked after every retry
                chat = self._client.post_chat(turn)
            except RefusedByChokepoint:
                raise
            except Exception as exc:
                raise _typed(exc) from exc
            box["text"] = chat.text
            box["status"] = chat.status
            return Outcome(output=chat.text, incurred_usd=self._chat_reserve, http_status=chat.status)

        return send

    def _turn_maker(self, turn: str, box: dict[str, Any]) -> Callable[[int], Callable[[], Outcome]]:
        def make(attempt: int) -> Callable[[], Outcome]:
            return self._turn_send(turn, attempt, box)

        return make

    def _refund(self, correlation_id: str, step: int, column: str) -> None:
        """A step refused before anything was sent is not counted. Only an abandoned row that never reached `sent`."""
        row = self._journal.latest(correlation_id, step)
        if row is not None and row.attempt == 0 and row.state == "abandoned" and (row.detail or "").startswith(("reserve_refused", "refused")):
            self._conn.execute(
                f"UPDATE campaigns SET {column} = MAX({column} - 1, 0) WHERE correlation_id = ?",  # nosec B608
                (correlation_id,),
            )
            self._conn.commit()

    def run(
        self, correlation_id: str, turns: tuple[str, ...], transcript_id: str, *, resume: int | None = None
    ) -> SequenceResult:
        """Preflight, then setup, then each turn. Raises PreflightRefused with nothing sent and nothing counted.

        An unknown outcome raises UnknownOutcome and is never replayed. Any other halt is returned in the result with
        the transcript of the turns that did complete. The sequence stops at the first refusal, error, 429 or 503.
        """
        if resume is None:
            preflight(
                self._conn, correlation_id, len(turns), self._config, self._client,
                chat_reserve_usd=self._chat_reserve, request_cap=self._request_cap,
            )
            number = int(require_campaign(self._conn, correlation_id)["sequences_started"]) + 1
        else:
            number = resume  # an in-flight sequence: its counter bump is committed and is never repeated
        sid = sequence_id_for(correlation_id, number)
        base = SEQUENCE_STEP_BASE + number * STEPS_PER_SEQUENCE
        result = SequenceResult(sid, resumed=resume is not None)
        fact_start = len(self._client.facts)
        policy = self._config.retry
        bump_sequence = (
            "UPDATE campaigns SET sequences_started = sequences_started + 1 WHERE correlation_id = ?",
            (correlation_id,),
        )
        try:
            run_step(
                self._journal, self._conn, policy, correlation_id, base, role="executor", kind="target",
                intent=f"setup {sid}", reserve_usd=0.0, make_send=self._setup_send, sleep=self._sleep,
                sequence_id=sid, extra_sql=bump_sequence,
            )
        except StepHalt as exc:
            self._refund(correlation_id, base, "sequences_started")
            result.halt = exc.halt
            result.facts = list(self._client.facts[fact_start:])
            return result
        records: list[dict[str, str]] = []
        for index, turn in enumerate(turns):
            step = base + 1 + index
            prior = self._journal.latest(correlation_id, step) if resume is not None else None
            if prior is not None and prior.state == "completed":
                result.unrecordable = True  # never re-sent. Only the output hash survives, not the text.
                break
            box: dict[str, Any] = {}
            bump_turn = (
                "UPDATE campaigns SET turns_sent = turns_sent + 1 WHERE correlation_id = ?",
                (correlation_id,),
            )
            try:
                run_step(
                    self._journal, self._conn, policy, correlation_id, step, role="executor", kind="target",
                    intent=f"turn {sid} {index}", reserve_usd=self._chat_reserve,
                    make_send=self._turn_maker(turn, box),
                    sleep=self._sleep, sequence_id=sid, extra_sql=bump_turn,
                )
            except StepHalt as exc:
                self._refund(correlation_id, step, "turns_sent")
                result.halt = exc.halt
                break
            text = str(box.get("text") or "(empty)")[:8000]
            records.append({"role": "user", "content": turn[:8000]})
            records.append({"role": "target", "content": text})
            result.turns_sent += 1
            result.texts.append(text)
            result.status = int(box.get("status") or 200)
        if records and not result.unrecordable:
            body: dict[str, Any] = {
                "transcript_id": transcript_id,
                "correlation_id": correlation_id,
                "schema_version": "v1",
                "recorded_by": "executor",
                "turns": records,
            }
            if result.status is not None:
                body["http_status"] = result.status
            result.transcript = body
        result.facts = list(self._client.facts[fact_start:])
        return result
