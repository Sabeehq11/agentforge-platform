"""Write-ahead dispatch journal. One row per external effect, committed before the effect it describes.

Order for every call: insert `intended` and reserve in the ledger, mark `sent`, call the transport, mark
`completed` with settlement `pending`, then incur in the ledger and mark `settled`. After a crash:

- intended: nothing was sent. The reservation is closed and the row is abandoned. agent_spend.call_id is single use,
  so the call goes out under the next attempt number, never under a call_id that was already reserved.
- sent or unknown: the request may have left the process. It is never replayed. The reservation is held against the
  shared ceiling. Only accept_unknown closes it, through Ledger.settle_orphan.
- completed: the effect is never re-sent. reconcile() settles the ledger side exactly once.

The journal stores hashes and statuses. It never stores a request body, a cookie or a credential.
"""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any

from agentforge.contracts.validate import ContractError
from agentforge.orchestrator.state import now_iso
from agentforge.safety.ledger import Ledger, LedgerError

KINDS = ("model", "target", "judge_model")
ROLES = ("orchestrator", "red_team", "executor", "judge")
_LEDGER_ROLE = {"red_team": "red_team", "judge": "judge", "executor": "target", "orchestrator": "red_team"}


class UnknownOutcome(Exception):
    """A call is stuck in sent or unknown. It is not replayed. The campaign halts as target_unreachable."""

    def __init__(self, call_id: str) -> None:
        self.call_id = call_id
        super().__init__("unknown_outcome")


class KillPoint(Exception):
    """Raised by a test hook to simulate a process kill at a named point."""


Hook = Callable[[str], None]


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def call_id_for(role: str, correlation_id: str, step_no: int, attempt: int) -> str:
    return f"{role}-{correlation_id}-{step_no}-{attempt}"


def parse_retry_after(value: str | None, *, now: datetime | None = None) -> float | None:
    """Delta-seconds or an HTTP date. A malformed value is None, which is treated as absent."""
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    if text.isascii() and text.isdigit():
        return float(int(text))
    try:
        when = parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0.0, (when - (now or datetime.now(timezone.utc))).total_seconds())


@dataclass(frozen=True)
class Entry:
    id: int
    correlation_id: str
    step_no: int
    attempt: int
    call_id: str
    role: str
    kind: str
    state: str
    reserved_usd: float
    incurred_usd: float
    http_status: int | None
    retry_after_s: float | None
    output_hash: str | None
    settlement: str
    sequence_id: str | None
    detail: str | None


_COLUMNS = (
    "id, correlation_id, step_no, attempt, call_id, role, kind, state, reserved_usd, incurred_usd, "
    "http_status, retry_after_s, output_hash, settlement, sequence_id, detail"
)


class Journal:
    """Crash-safe dispatch. The ledger and the journal share one SQLite connection."""

    def __init__(self, conn: sqlite3.Connection, ledger: Ledger, *, hook: Hook | None = None) -> None:
        self._conn = conn
        self._ledger = ledger
        self._hook = hook

    def point(self, name: str) -> None:
        """A named kill point. A test hook raises here to simulate a process kill."""
        if self._hook is not None:
            self._hook(name)

    # reads -------------------------------------------------------------------------------------------------
    def get(self, call_id: str) -> Entry | None:
        row = self._conn.execute(f"SELECT {_COLUMNS} FROM dispatch_journal WHERE call_id = ?", (call_id,)).fetchone()  # nosec B608
        return Entry(*row) if row else None

    def rows(self, correlation_id: str) -> list[Entry]:
        found = self._conn.execute(
            f"SELECT {_COLUMNS} FROM dispatch_journal WHERE correlation_id = ? ORDER BY id", (correlation_id,)  # nosec B608
        ).fetchall()
        return [Entry(*r) for r in found]

    def latest(self, correlation_id: str, step_no: int) -> Entry | None:
        row = self._conn.execute(
            f"SELECT {_COLUMNS} FROM dispatch_journal WHERE correlation_id = ? AND step_no = ? ORDER BY attempt DESC LIMIT 1",  # nosec B608
            (correlation_id, step_no),
        ).fetchone()
        return Entry(*row) if row else None

    def ledger_state(self, call_id: str) -> str | None:
        row = self._conn.execute("SELECT state FROM agent_spend WHERE call_id = ?", (call_id,)).fetchone()
        return None if row is None else str(row[0])

    def _set(self, call_id: str, **fields: Any) -> None:
        names = ", ".join(f"{name} = ?" for name in fields)
        self._conn.execute(  # nosec B608
            f"UPDATE dispatch_journal SET {names}, updated_at = ? WHERE call_id = ?",
            (*fields.values(), now_iso(), call_id),
        )

    # ledger helpers. A fresh Ledger after a crash holds no open reservation, so it closes through settle_orphan
    def _close_incur(self, call_id: str, usd: float) -> None:
        try:
            self._ledger.incur(call_id, usd)
        except LedgerError:
            if self.ledger_state(call_id) != "reserved":
                raise
            self._ledger.settle_orphan(call_id, usd)

    def _close_release(self, call_id: str) -> None:
        if self.ledger_state(call_id) != "reserved":
            return
        try:
            self._ledger.release(call_id)
        except LedgerError:
            self._ledger.settle_orphan(call_id)

    # write-ahead steps -------------------------------------------------------------------------------------
    def intend(
        self,
        correlation_id: str,
        step_no: int,
        attempt: int,
        *,
        role: str,
        kind: str,
        intent: str,
        reserve_usd: float,
        sequence_id: str | None = None,
        extra_sql: tuple[str, tuple[Any, ...]] | None = None,
    ) -> Entry:
        """Step 1. Insert `intended`, then reserve under the same call_id. A refused reserve abandons the row.

        extra_sql lets the caller bump a counter in the same transaction as the intended row.
        """
        if role not in ROLES or kind not in KINDS:
            raise ValueError("unknown journal role or kind")
        call_id = call_id_for(role, correlation_id, step_no, attempt)
        when = now_iso()
        self.point("before_insert")
        try:
            self._conn.execute(
                """
                INSERT INTO dispatch_journal (correlation_id, step_no, attempt, call_id, role, kind, intent_hash, state,
                    reserved_usd, settlement, sequence_id, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'intended', ?, 'none', ?, ?, ?)
                """,
                (correlation_id, step_no, attempt, call_id, role, kind, sha256_hex(intent), reserve_usd, sequence_id, when, when),
            )
            if extra_sql is not None:
                self._conn.execute(extra_sql[0], extra_sql[1])
            self._conn.commit()
        except sqlite3.IntegrityError as exc:
            self._conn.rollback()
            raise ContractError("dispatch_journal", f"call {call_id} already exists") from exc
        self.point("after_intended_insert")
        try:
            self._ledger.reserve(call_id, _LEDGER_ROLE[role], reserve_usd)
        except Exception:
            self._set(call_id, state="abandoned", settlement="released", detail="reserve_refused")
            self._conn.commit()
            raise
        self.point("after_reserve")
        entry = self.get(call_id)
        assert entry is not None
        return entry

    def mark_sent(self, call_id: str) -> None:
        """Step 2. Committed before the transport is called."""
        self._set(call_id, state="sent")
        self._conn.commit()
        self.point("after_sent")

    def complete(
        self,
        call_id: str,
        *,
        output: str,
        incurred_usd: float,
        http_status: int | None = None,
        retry_after_s: float | None = None,
    ) -> None:
        """Step 3a. Record the outcome with settlement pending, committed before the ledger is touched. Then settle."""
        entry = self.get(call_id)
        if entry is None:
            raise ContractError("dispatch_journal", f"unknown call {call_id}")
        if incurred_usd < 0 or incurred_usd > entry.reserved_usd + 1e-12:
            raise ContractError("dispatch_journal", "incurred amount must be between zero and the reservation")
        self._set(
            call_id,
            state="completed",
            output_hash=sha256_hex(output),
            incurred_usd=incurred_usd,
            http_status=http_status,
            retry_after_s=retry_after_s,
            settlement="pending",
        )
        self._conn.commit()
        self.point("after_completed")
        self.reconcile_one(call_id)
        self.point("after_settled")

    def annotate(self, call_id: str, detail: str) -> None:
        """Attach a short note to a row without touching its state, for example `rejected`. Never a body or a secret."""
        self._set(call_id, detail=detail[:200])
        self._conn.commit()

    # typed failures ----------------------------------------------------------------------------------------
    def record_unknown(self, call_id: str, detail: str = "unknown_outcome") -> None:
        """A transport error after the request was written. The reservation is held and the call is never retried."""
        self._set(call_id, state="unknown", detail=detail[:200])
        self._conn.commit()

    def fail(
        self,
        call_id: str,
        *,
        http_status: int | None = None,
        retry_after_s: float | None = None,
        detail: str,
    ) -> None:
        """The target answered with a status that billed nothing, or a local gate refused before any send.

        The status and Retry-After are stored verbatim. The reservation is released, which is allowed only because
        no billable work is known to have happened. An unknown outcome never takes this path.
        """
        entry = self.get(call_id)
        if entry is None:
            raise ContractError("dispatch_journal", f"unknown call {call_id}")
        if entry.state in ("completed", "unknown"):
            raise ContractError("dispatch_journal", "a completed or unknown call must not be released")
        self._close_release(call_id)
        self._set(
            call_id,
            state="abandoned",
            settlement="released",
            http_status=http_status,
            retry_after_s=retry_after_s,
            detail=detail[:200],
        )
        self._conn.commit()

    # reconcile ---------------------------------------------------------------------------------------------
    def reconcile_one(self, call_id: str) -> str:
        """Settle one completed entry exactly once. Returns incurred, marked or noop.

        settlement is the idempotency key. The amount is the journal's incurred_usd and is never recomputed.
        """
        entry = self.get(call_id)
        if entry is None:
            raise ContractError("dispatch_journal", f"unknown call {call_id}")
        if entry.state != "completed" or entry.settlement != "pending":
            return "noop"
        if entry.incurred_usd > entry.reserved_usd + 1e-12:
            raise ContractError("dispatch_journal", "journal incurred amount exceeds the reservation")
        state = self.ledger_state(call_id)
        if state is None:
            raise ContractError("dispatch_journal", f"completed call {call_id} has no ledger row")
        if state == "released":
            raise ContractError("dispatch_journal", f"completed call {call_id} was released in the ledger")
        done = "marked"
        if state == "reserved":
            self._close_incur(call_id, entry.incurred_usd)
            done = "incurred"
            self.point("after_incur")
        self._set(call_id, settlement="settled")
        self._conn.commit()
        return done

    def reconcile(self, correlation_id: str) -> list[str]:
        """Settle every completed entry that is still pending. Safe to run twice. Touches no other state."""
        settled: list[str] = []
        for entry in self.rows(correlation_id):
            if entry.state == "completed" and entry.settlement == "pending":
                if self.reconcile_one(entry.call_id) != "noop":
                    settled.append(entry.call_id)
        return settled

    # resume ------------------------------------------------------------------------------------------------
    def stuck(self, correlation_id: str) -> list[Entry]:
        """Rows in sent or unknown. Never replayed."""
        return [e for e in self.rows(correlation_id) if e.state in ("sent", "unknown")]

    def intended(self, correlation_id: str) -> list[Entry]:
        return [e for e in self.rows(correlation_id) if e.state == "intended"]

    def resume_check(self, correlation_id: str) -> list[Entry]:
        """Run before any new dispatch. Reconciles completed rows, raises on an unknown outcome, returns intended rows.

        The transport is never called here.
        """
        self.reconcile(correlation_id)
        stuck = self.stuck(correlation_id)
        if stuck:
            raise UnknownOutcome(stuck[0].call_id)
        return self.intended(correlation_id)

    def adopt(self, call_id: str) -> Entry | None:
        """Make an `intended` row ready to dispatch under the same call_id, with exactly one reservation.

        A reservation still open in the ledger is adopted, not reserved again. A row with no ledger row (killed
        between the insert and the reserve) is reserved now. A closed reservation cannot be reused: the row is
        abandoned and the caller uses the next attempt number.
        """
        entry = self.get(call_id)
        if entry is None or entry.state != "intended":
            raise ContractError("dispatch_journal", f"call {call_id} is not intended")
        state = self.ledger_state(call_id)
        if state is None:
            self._ledger.reserve(call_id, _LEDGER_ROLE[entry.role], entry.reserved_usd)
            return entry
        if state == "reserved":
            return entry
        self._set(call_id, state="abandoned", settlement="released", detail="reservation_not_reusable")
        self._conn.commit()
        return None

    def accept_unknown(self, call_id: str, *, evidence_usd: float | None = None) -> Entry:
        """Operator action. Closes a sent or unknown call through Ledger.settle_orphan, never reserving a second time.

        With no evidence the call is recorded as incurred at the reserved amount, because the operator cannot confirm
        it did not bill. With evidence_usd the settled amount is that value, at most the reservation. A second accept
        is refused.
        """
        entry = self.get(call_id)
        if entry is None:
            raise ContractError("dispatch_journal", f"unknown call {call_id}")
        if entry.state not in ("sent", "unknown"):
            raise ContractError("dispatch_journal", f"call {call_id} is not an unknown outcome")
        if self.ledger_state(call_id) != "reserved":
            raise ContractError("dispatch_journal", f"call {call_id} has no held reservation")
        amount = entry.reserved_usd if evidence_usd is None else evidence_usd
        if amount < 0 or amount > entry.reserved_usd + 1e-12:
            raise ContractError("dispatch_journal", "evidence amount must be between zero and the reservation")
        self._close_incur(call_id, amount)
        self._set(call_id, state="abandoned", settlement="settled", incurred_usd=amount, detail="accepted_unknown")
        self._conn.commit()
        updated = self.get(call_id)
        assert updated is not None
        return updated

    def next_attempt(self, correlation_id: str, step_no: int) -> int:
        last = self.latest(correlation_id, step_no)
        return 0 if last is None else last.attempt + 1


@dataclass(frozen=True)
class Outcome:
    """What a send callable reports. output is hashed, never stored."""

    output: str
    incurred_usd: float = 0.0
    http_status: int | None = None
    retry_after_s: float | None = None


class Refused(Exception):
    """A local gate refused before any request left the process. The reservation is released."""

    def __init__(self, gate: str, reason: str) -> None:
        self.gate = gate
        self.reason = reason
        super().__init__(f"{gate}: {reason}")


class NotSent(Exception):
    """A connection error proven to occur before the request was written. Nothing billed, so the call is retryable."""


class Answered(Exception):
    """The target answered with a status that did not bill (429, 503 or another refusal). Status is kept verbatim."""

    def __init__(self, http_status: int, retry_after_s: float | None, detail: str) -> None:
        self.http_status = http_status
        self.retry_after_s = retry_after_s
        super().__init__(detail)


def dispatch(
    journal: Journal,
    correlation_id: str,
    step_no: int,
    attempt: int,
    *,
    role: str,
    kind: str,
    intent: str,
    reserve_usd: float,
    send: Callable[[], Outcome],
    sequence_id: str | None = None,
    extra_sql: tuple[str, tuple[Any, ...]] | None = None,
) -> Outcome:
    """The full write-ahead order for one external effect.

    Refused (a local gate) and Answered (a non-billing status) release the reservation and re-raise. An OSError after
    the request may have been written records `unknown`, holds the reservation and raises UnknownOutcome. Any other
    exception, including a test kill, propagates and leaves the journal exactly as it was committed.
    """
    entry = journal.intend(
        correlation_id, step_no, attempt, role=role, kind=kind, intent=intent, reserve_usd=reserve_usd,
        sequence_id=sequence_id, extra_sql=extra_sql,
    )
    call_id = entry.call_id
    journal.mark_sent(call_id)
    try:
        outcome = send()
    except Refused as exc:
        journal.fail(call_id, detail=f"refused {exc.gate}")
        raise
    except Answered as exc:
        journal.fail(call_id, http_status=exc.http_status, retry_after_s=exc.retry_after_s, detail=f"status {exc.http_status}")
        raise
    except NotSent as exc:
        journal.fail(call_id, detail=f"not_sent {exc}"[:200])
        raise
    except OSError as exc:
        journal.record_unknown(call_id, type(exc).__name__)
        raise UnknownOutcome(call_id) from exc
    journal.point("after_transport")
    journal.complete(
        call_id,
        output=outcome.output,
        incurred_usd=outcome.incurred_usd,
        http_status=outcome.http_status,
        retry_after_s=outcome.retry_after_s,
    )
    return outcome
