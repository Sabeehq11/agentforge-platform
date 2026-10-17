"""Cost controls: per-run and per-day USD caps, an attack-count cap, an approval token and a kill switch.

The token is bound to the exact numbers (the target repo's scripts/w2/measure.py pattern), so changing a cap
invalidates an earlier approval. Nothing here calls a provider.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


class BudgetError(Exception):
    """Base class. Raised before the call that would break a rule, never after."""


class BudgetExceeded(BudgetError):
    pass


class KillSwitchEngaged(BudgetError):
    pass


class NotApproved(BudgetError):
    pass


@dataclass(frozen=True)
class Caps:
    per_run_usd: float
    per_day_usd: float
    max_attacks_per_run: int
    hard_ceiling_per_run_usd: float
    hard_ceiling_per_day_usd: float


def approval_token(caps: Caps, secret: str) -> str:
    """Token bound to the exact cap numbers. The operator computes it; the secret is never stored in the repo."""
    msg = (
        f"{caps.per_run_usd:.6f}|{caps.per_day_usd:.6f}|{caps.max_attacks_per_run}|"
        f"{caps.hard_ceiling_per_run_usd:.6f}|{caps.hard_ceiling_per_day_usd:.6f}"
    )
    return hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()


def load_caps(path: str | Path) -> Caps:
    data: Any = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("budget config must be a mapping")
    caps = Caps(
        per_run_usd=float(data["per_run_usd"]),
        per_day_usd=float(data["per_day_usd"]),
        max_attacks_per_run=int(data["max_attacks_per_run"]),
        hard_ceiling_per_run_usd=float(data["hard_ceiling_per_run_usd"]),
        hard_ceiling_per_day_usd=float(data["hard_ceiling_per_day_usd"]),
    )
    values = (caps.per_run_usd, caps.per_day_usd, caps.hard_ceiling_per_run_usd, caps.hard_ceiling_per_day_usd)
    if any(v < 0 for v in values) or caps.max_attacks_per_run < 0:
        raise ValueError("budget caps must not be negative")
    if caps.per_run_usd > caps.hard_ceiling_per_run_usd or caps.per_day_usd > caps.hard_ceiling_per_day_usd:
        raise ValueError("a cap exceeds its hard ceiling")
    return caps


class Budget:
    """Reserve before spending. Unapproved budgets reserve nothing."""

    def __init__(self, caps: Caps) -> None:
        self._caps = caps
        self._approved = False
        self._killed = False
        self._run_spent = 0.0
        self._day_spent = 0.0
        self._attacks = 0

    @property
    def caps(self) -> Caps:
        return self._caps

    @property
    def killed(self) -> bool:
        return self._killed

    @property
    def run_spent(self) -> float:
        return self._run_spent

    @property
    def day_spent(self) -> float:
        return self._day_spent

    @property
    def attacks(self) -> int:
        return self._attacks

    def approve(self, token: str, secret: str) -> None:
        if not secret or not hmac.compare_digest(token, approval_token(self._caps, secret)):
            raise NotApproved("approval token does not match the exact budget numbers")
        self._approved = True

    def kill(self) -> None:
        """Halt before the next call. Irreversible for this object."""
        self._killed = True

    def start_run(self) -> None:
        self._run_spent = 0.0
        self._attacks = 0

    def reserve(self, usd: float, *, attack: bool = True) -> None:
        if self._killed:
            raise KillSwitchEngaged("kill switch engaged")
        if not self._approved:
            raise NotApproved("budget is not approved")
        if usd < 0:
            raise ValueError("reserve amount must not be negative")
        if self._run_spent + usd > self._caps.per_run_usd:
            raise BudgetExceeded("per-run cap would be exceeded")
        if self._day_spent + usd > self._caps.per_day_usd:
            raise BudgetExceeded("per-day cap would be exceeded")
        if attack and self._attacks + 1 > self._caps.max_attacks_per_run:
            raise BudgetExceeded("attack-count cap would be exceeded")
        self._run_spent += usd
        self._day_spent += usd
        if attack:
            self._attacks += 1
