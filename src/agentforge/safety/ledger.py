"""Per-agent cost ledger. Reserved budget and incurred spend are separate and are never added together.

A refused reserve writes nothing. Incurred spend is written only after a call is accepted. Releasing an
unused reservation decreases reserved and does not touch incurred. One accepted call has one incurred line.

Target-side amounts are fixture or operator-supplied. This module does not call a usage API.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from agentforge.safety.budget import Budget, BudgetError, BudgetExceeded, Caps

ROLES = ("red_team", "judge", "target")
SHARED_CEILING_USD = 5.0


class LedgerError(Exception):
    pass


@dataclass(frozen=True)
class Totals:
    reserved_usd: float
    incurred_usd: float


def committed_usd(conn: sqlite3.Connection) -> float:
    """Open reservations plus incurred spend. A released reservation no longer counts."""
    row = conn.execute(
        """
        SELECT COALESCE(SUM(
            CASE
                WHEN state = 'reserved' THEN reserved_usd
                WHEN state = 'incurred' THEN incurred_usd
                ELSE 0
            END
        ), 0)
        FROM agent_spend
        """
    ).fetchone()
    return float(row[0] if row is not None else 0.0)


def load_shared_budget(conn: sqlite3.Connection, caps: Caps, token: str, secret: str) -> Budget:
    """Approve a fresh Budget, then reserve the ledger's already committed amount.

    A later process therefore cannot spend another full cap. The seed is not an attack.
    """
    budget = Budget(caps)
    budget.approve(token, secret)
    committed = committed_usd(conn)
    if committed > SHARED_CEILING_USD or committed > caps.per_run_usd or committed > caps.per_day_usd:
        raise BudgetExceeded("shared ceiling is already exhausted")
    if committed:
        budget.reserve(committed, attack=False)
    return budget


class Ledger:
    """Attributes each reservation to a role, then delegates the cap check to Budget."""

    def __init__(self, conn: sqlite3.Connection, budget: Budget) -> None:
        self._conn = conn
        self._budget = budget
        self._open: dict[str, tuple[str, float]] = {}

    def reserve(self, call_id: str, role: str, usd: float) -> None:
        """Write the reserved column, then ask Budget. A refusal rolls the row back, so nothing remains."""
        if role not in ROLES:
            raise LedgerError(f"unknown role {role}")
        if call_id in self._open:
            raise LedgerError(f"call {call_id} is already reserved")
        if usd < 0:
            raise LedgerError("reserve amount must not be negative")
        self._conn.execute(
            "INSERT INTO agent_spend (call_id, agent_role, reserved_usd, incurred_usd, state) VALUES (?, ?, ?, 0, 'reserved')",
            (call_id, role, usd),
        )
        try:
            if committed_usd(self._conn) > SHARED_CEILING_USD:
                raise BudgetExceeded("shared ceiling would be exceeded")
            self._budget.reserve(usd, attack=role != "judge")
        except BudgetError:
            self._conn.execute("DELETE FROM agent_spend WHERE call_id = ?", (call_id,))
            self._conn.commit()
            raise
        self._conn.commit()
        self._open[call_id] = (role, usd)

    def incur(self, call_id: str, usd: float) -> None:
        """Record incurred spend for an accepted call. Rejected calls must not call this."""
        if call_id not in self._open:
            raise LedgerError(f"call {call_id} has no open reservation")
        if usd < 0:
            raise LedgerError("incurred amount must not be negative")
        row = self._conn.execute(
            "SELECT incurred_usd, state FROM agent_spend WHERE call_id = ?", (call_id,)
        ).fetchone()
        if row is None or row[1] != "reserved" or row[0] != 0:
            raise LedgerError(f"call {call_id} already has incurred spend")
        self._conn.execute(
            "UPDATE agent_spend SET incurred_usd = ?, state = 'incurred' WHERE call_id = ?",
            (usd, call_id),
        )
        self._conn.commit()
        del self._open[call_id]

    def release(self, call_id: str) -> None:
        """Return an unused reservation to the budget. Does not add a negative incurred row."""
        if call_id not in self._open:
            raise LedgerError(f"call {call_id} has no open reservation")
        role, usd = self._open[call_id]
        self._budget.release(usd, attack=role != "judge")
        self._conn.execute(
            "UPDATE agent_spend SET reserved_usd = 0, state = 'released' WHERE call_id = ?",
            (call_id,),
        )
        self._conn.commit()
        del self._open[call_id]

    def settle_orphan(self, call_id: str, usd: float | None = None) -> None:
        """Close a reservation left open by a process that no longer exists.

        Only a row still in state reserved that this instance did not open is accepted. With usd None the row is
        released and nothing is charged. A usd is written only when the caller holds provider evidence for that
        exact call. The amount must not exceed what was reserved. A row that is already closed is refused.
        """
        if call_id in self._open:
            raise LedgerError(f"call {call_id} is open in this process, settle it with release or incur")
        row = self._conn.execute(
            "SELECT reserved_usd, state FROM agent_spend WHERE call_id = ?", (call_id,)
        ).fetchone()
        if row is None or row[1] != "reserved":
            raise LedgerError(f"call {call_id} has no orphaned reservation")
        if usd is None:
            self._conn.execute(
                "UPDATE agent_spend SET reserved_usd = 0, state = 'released' WHERE call_id = ?", (call_id,)
            )
        else:
            if usd < 0 or usd > float(row[0]):
                raise LedgerError("evidence amount must be between zero and the reservation")
            self._conn.execute(
                "UPDATE agent_spend SET incurred_usd = ?, state = 'incurred' WHERE call_id = ?", (usd, call_id)
            )
        self._conn.commit()

    def totals(self, role: str | None = None) -> Totals:
        if role is None:
            row = self._conn.execute(
                "SELECT COALESCE(SUM(reserved_usd), 0), COALESCE(SUM(incurred_usd), 0) FROM agent_spend"
            ).fetchone()
        else:
            row = self._conn.execute(
                "SELECT COALESCE(SUM(reserved_usd), 0), COALESCE(SUM(incurred_usd), 0) FROM agent_spend WHERE agent_role = ?",
                (role,),
            ).fetchone()
        assert row is not None
        return Totals(float(row[0]), float(row[1]))

    def combined(self, call_id: str) -> float:
        """Forbidden view. Tests call this to prove reserved and incurred are not one number."""
        raise LedgerError("reserved and incurred must not be summed for a call")
