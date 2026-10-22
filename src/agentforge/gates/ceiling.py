"""The $12.00 lifetime ceiling (plan section 7). Exposure E = I + O + X.

- I: incurred ledger spend (state `incurred`).
- O: open reservations (state `reserved`), counted at the reserved amount. Uncertain outcomes are a subset of O and
  count in full. They are never released to $0 without evidence that no request was sent.
- X: recorded excess, a charge shown by bill evidence to exceed the recorded amount.

A new reservation r is admitted only if I + O + X + r is at most $12.00. Planned reservations are also limited to a
$10.35 cumulative, which leaves $1.65 for uncertain outcomes and excess. Excluded: Budget's double count (headroom,
not spend), other users' spend on the shared key, the $300 balance, projections, and the D-13 stub run.

Code enforces only I + O against the $5.00 SHARED_CEILING_USD. This module does not read the ledger. The figures
come from a human-filled spend-reconciliation record, so no database is opened here.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from decimal import Decimal
from pathlib import Path
from typing import Any

from agentforge.gates.common import load_mapping, parse_date, to_decimal

CEILING_USD = Decimal("12.00")
PLANNED_LIMIT_USD = Decimal("10.35")
MARGIN_USD = Decimal("1.65")
MAX_RECORD_AGE_DAYS = 1  # ledger totals move, so a stale record is not a basis for admitting a reservation


@dataclass(frozen=True)
class Exposure:
    incurred: Decimal
    open_reserved: Decimal
    uncertain: Decimal
    excess: Decimal

    @property
    def total(self) -> Decimal:
        # Uncertain outcomes are inside open_reserved. They are listed, not added a second time.
        return self.incurred + self.open_reserved + self.excess


@dataclass(frozen=True)
class Admission:
    """The result of admit(). `allowed` is true exactly when `blocking` is empty.

    `notices` never block. They must still be carried into the approval request. `uncertain_usd` is the amount of
    uncertain outcomes that the request has to list, a number and not a message to be matched by text.
    """

    allowed: bool
    total_after: Decimal | None
    blocking: tuple[str, ...]
    notices: tuple[str, ...] = ()
    uncertain_usd: Decimal = Decimal("0")

    @property
    def reasons(self) -> tuple[str, ...]:
        """Blocking reasons first, then notices, for display only. Nothing decides on this text."""
        return self.blocking + self.notices


def exposure_from_record(
    record: dict[str, Any] | None, *, today: date
) -> tuple[Exposure | None, list[str]]:
    """The exposure from a spend-reconciliation record, or None with the reasons it cannot be used."""
    if record is None:
        return None, ["spend-reconciliation record is missing or unreadable"]
    problems: list[str] = []
    values: dict[str, Decimal] = {}
    for key in ("incurred_usd", "open_reserved_usd", "uncertain_usd", "excess_usd"):
        amount = to_decimal(record.get(key))
        if amount is None:
            problems.append(f"{key} must be a non-negative amount")
        else:
            values[key] = amount
    as_of = parse_date(record.get("as_of"))
    if as_of is None:
        problems.append("as_of must be an ISO date")
    elif as_of > today:
        problems.append("as_of is in the future")
    elif (today - as_of).days > MAX_RECORD_AGE_DAYS:
        problems.append(f"as_of is older than {MAX_RECORD_AGE_DAYS} day")
    if problems:
        return None, problems
    if values["uncertain_usd"] > values["open_reserved_usd"]:
        return None, [
            "uncertain_usd is a subset of open_reserved_usd and cannot exceed it"
        ]
    return (
        Exposure(
            values["incurred_usd"],
            values["open_reserved_usd"],
            values["uncertain_usd"],
            values["excess_usd"],
        ),
        [],
    )


def admit(
    exposure: Exposure,
    request_usd: Decimal,
    *,
    planned_cumulative_usd: Decimal | None = None,
) -> Admission:
    """Admit a reservation only if I + O + X + r stays within $12.00, and planned spend within $10.35."""
    blocking: list[str] = []
    notices: list[str] = []
    after = exposure.total + request_usd
    if exposure.total > CEILING_USD:
        blocking.append(
            "exposure already exceeds the ceiling: all billable work halts for re-planning"
        )
    if after > CEILING_USD:
        blocking.append(
            f"I + O + X + r would be {after}, above the {CEILING_USD} ceiling"
        )
    if (
        planned_cumulative_usd is not None
        and planned_cumulative_usd + request_usd > PLANNED_LIMIT_USD
    ):
        blocking.append(
            f"planned reservations would exceed the {PLANNED_LIMIT_USD} cumulative limit"
        )
    if exposure.uncertain > 0:
        notices.append(
            f"unresolved uncertain outcomes ({exposure.uncertain}) must be listed in the approval request"
        )
    return Admission(
        allowed=not blocking,
        total_after=after,
        blocking=tuple(blocking),
        notices=tuple(notices),
        uncertain_usd=exposure.uncertain,
    )


def load_exposure(path: Path, *, today: date) -> tuple[Exposure | None, list[str]]:
    return exposure_from_record(load_mapping(path), today=today)
