"""The single HTTP chokepoint. Every request to the target must go through request().

Gate order: allowlist, budget, spend-limit attestation, request-rate cap, then the injected transport. If any gate
fails the transport is never called, and the refusal is logged (host, gate, reason only). Headers and a body may
be passed to the transport. They are not written to the refusal log.

LIVE_ENABLED is the kill switch. It stays False in committed code. An environment variable, a CLI flag, or any
other runtime setting cannot set it or skip this check. Turning it on is a reviewed source change, not a config
toggle. fake_transport is the unit-test seam only. It is not read from the environment and is not a live bypass.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date

from .allowlist import Allowlist
from .budget import Budget
from .rate import RateCap, RateCapExceeded
from .refusal_log import RefusalLog
from .spend_limits import Attestation, require_attested

# Authoritative kill switch. Reviewed source change required to enable a live transport. Not an env flag.
LIVE_ENABLED = False

# Names that must not be consulted. Present so a later edit that reads them is obvious in review.
_IGNORED_ENV = ("AGENTFORGE_LIVE", "LIVE_ENABLED", "AGENTFORGE_LIVE_ENABLED")


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
    headers: dict[str, str] | None = None


# method, url, then optional headers and body. Two-argument callables still work: the extras are keyword-only.
Transport = Callable[..., Response]


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
    rate_cap: RateCap | None = None,
    refusal_log: RefusalLog | None = None,
    headers: dict[str, str] | None = None,
    body: bytes | str | None = None,
) -> Response:
    """Send one request through every gate. Redirects are followed only if each hop is allowlisted.

    max_redirects defaults to 0: a redirect response is returned to the caller after its target is checked, not
    followed blindly. An off-list redirect target is logged and raises. A 429 or 503 is returned, never retried.
    """
    # Read and discard. These names cannot enable live use. The constant above is the only switch.
    for _name in _IGNORED_ENV:
        os.environ.get(_name)

    def refuse(gate: str, reason: str) -> RefusedByChokepoint:
        if refusal_log is not None:
            refusal_log.record(gate, reason, url)
        return RefusedByChokepoint(gate, reason)

    if not LIVE_ENABLED and not fake_transport:
        raise refuse("live", "live use is disabled (LIVE_ENABLED is False)")

    decision = allowlist.check(url)
    if not decision.allowed:
        raise refuse("allowlist", decision.reason)

    try:
        budget.reserve(est_cost_usd)
    except Exception as exc:  # BudgetError subclasses; kept generic so any budget failure stops the call
        raise refuse("budget", str(exc)) from exc

    try:
        require_attested(provider, attestations, today=today)
    except Exception as exc:
        raise refuse("spend_limit", str(exc)) from exc

    if rate_cap is not None:
        try:
            rate_cap.reserve()
        except RateCapExceeded as exc:
            raise refuse("rate", str(exc)) from exc

    current = url
    hops = 0
    while True:
        # Two-argument fakes stay valid. Headers and body are passed only when the caller supplied them.
        if headers is None and body is None:
            response = transport(method, current)
        else:
            response = transport(method, current, headers=headers, body=body)
        if response.status in (429, 503):
            return response
        if response.status in (301, 302, 303, 307, 308) and response.location:
            redirect = allowlist.check_redirect(current, response.location)
            if not redirect.allowed:
                raise refuse("allowlist", f"off-list redirect refused: {redirect.reason}")
            if hops >= max_redirects:
                return response
            hops += 1
            current = response.location
            continue
        return response
