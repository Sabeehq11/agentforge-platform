"""In-process write grants. Not an authenticated principal and not a database user.

issue_grant may be called only by CampaignLoop and the regression suite. An agent that imports it
fails the P9 static check. A role string on a record is not a grant. Direct SQL by the process
owner remains possible; ADR-005 records that limit.
"""

from __future__ import annotations

from dataclasses import dataclass

ROLES = frozenset({"judge", "documentation", "harness"})


class GrantRefused(Exception):
    """The write had no usable grant. The row is unchanged."""


@dataclass(frozen=True)
class Grant:
    """A capability issued by a trusted boundary. The name is a label, not a proof of identity."""

    role: str


def issue_grant(role: str) -> Grant:
    """Issue one grant. Callers outside the campaign loop and the suite are a review failure."""
    if role not in ROLES:
        raise GrantRefused(f"no grant exists for {role!r}")
    return Grant(role)


def grant_for_test(role: str) -> Grant:
    """A grant for tests that seed rows. Production callers use issue_grant at the trusted boundary."""
    return issue_grant(role)


def require_grant(grant: Grant | None, role: str) -> None:
    """Refuse a missing, forged, or mismatched grant before any write."""
    if not isinstance(grant, Grant) or grant.role != role:
        raise GrantRefused(f"this write requires a {role} grant issued by a trusted boundary")
