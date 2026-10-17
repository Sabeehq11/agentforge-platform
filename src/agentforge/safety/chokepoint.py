"""The single HTTP chokepoint. Every request to the target must go through request().

Gate order: allowlist, then budget, then spend-limit attestation, then the injected transport. If any gate fails the
transport is never called. LIVE_ENABLED is False in P0, so there is no real transport: tests inject a fake one, and
live use is refused outright.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import date

from .allowlist import Allowlist
from .budget import Budget
from .spend_limits import Attestation, require_attested

# P0 has no live transport. Enabling this is a reviewed change made at P3, after the full envelope is tested.
LIVE_ENABLED = False


class RefusedByChokepoint(Exception):
    def __init__(self, gate: str, reason: str) -> None:
        super().__init__(f"{gate}: {reason}")
        self.gate = gate
        self.reason = reason


@dataclass(frozen=True)
class Response:
    status: int
    body: bytes = b""
    location: str | None = None


Transport = Callable[[str, str], Response]


def request(
    method: str,
    url: str,
    *,
    transport: Transport,
    allowlist: Allowlist,
    budget: Budget,
    attestations: list[Attestation],
    provider: str,
    est_cost_usd: float,
    today: date,
    max_redirects: int = 0,
    fake_transport: bool = False,
) -> Response:
    """Send one request through every gate. Redirects are followed only if each hop is allowlisted.

    max_redirects defaults to 0: a redirect response is returned to the caller after its target is checked, not
    followed blindly. An off-list redirect target raises.
    """
    if not LIVE_ENABLED and not fake_transport:
        raise RefusedByChokepoint("live", "live use is disabled in P0 (LIVE_ENABLED is False)")

    decision = allowlist.check(url)
    if not decision.allowed:
        raise RefusedByChokepoint("allowlist", decision.reason)

    try:
        budget.reserve(est_cost_usd)
    except Exception as exc:  # BudgetError subclasses; kept generic so any budget failure stops the call
        raise RefusedByChokepoint("budget", str(exc)) from exc

    try:
        require_attested(provider, attestations, today=today)
    except Exception as exc:
        raise RefusedByChokepoint("spend_limit", str(exc)) from exc

    current = url
    hops = 0
    while True:
        response = transport(method, current)
        if response.status in (301, 302, 303, 307, 308) and response.location:
            redirect = allowlist.check_redirect(current, response.location)
            if not redirect.allowed:
                raise RefusedByChokepoint("allowlist", f"off-list redirect refused: {redirect.reason}")
            if hops >= max_redirects:
                return response
            hops += 1
            current = response.location
            continue
        return response
