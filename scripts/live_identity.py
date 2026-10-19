#!/usr/bin/env python3
"""Wire identity verification through the existing chokepoint. Makes no call unless LIVE_ENABLED is true.

Loads the committed allowlist, budget, and spend-limit files. Approves the budget with an operator token and
secret from the environment, then GETs the public login page through request(). Does not log in, post chat, or
write a result file. The secret is not stored. Running this while LIVE_ENABLED is false refuses before any socket.
"""

from __future__ import annotations

import os
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentforge.evals.session import SessionClient, real_transport  # noqa: E402
from agentforge.local_env import load_local_env  # noqa: E402
from agentforge.safety.allowlist import Allowlist  # noqa: E402
from agentforge.safety.budget import Budget, NotApproved, load_caps  # noqa: E402
from agentforge.safety.chokepoint import RefusedByChokepoint  # noqa: E402
from agentforge.safety.identity import IdentityMismatch  # noqa: E402
from agentforge.safety.rate import RateCap  # noqa: E402
from agentforge.safety.spend_limits import load_attestations  # noqa: E402

_TOKEN_ENV = "AGENTFORGE_BUDGET_TOKEN"
_SECRET_ENV = "AGENTFORGE_BUDGET_SECRET"
_ORIGIN_ENV = "AGENTFORGE_TARGET_ORIGIN"


def run_identity(
    root: Path,
    *,
    today: date,
    token: str,
    secret: str,
    origin: str,
) -> str:
    """Return 'pass' or a refusal line. Does not open a socket when LIVE_ENABLED is false."""
    allowlist = Allowlist.from_file(root / "config" / "allowlist.yaml")
    budget = Budget(load_caps(root / "config" / "budget.yaml"))
    budget.approve(token, secret)
    attestations = load_attestations(root / "config" / "spend_limits.yaml")
    client = SessionClient(
        origin,
        transport=real_transport,
        allowlist=allowlist,
        budget=budget,
        attestations=attestations,
        today=today,
        rate_cap=RateCap(1),
        fake_transport=False,
    )
    client.verify_identity()
    return "pass"


def main() -> int:
    load_local_env(ROOT / ".env")
    token = os.environ.get(_TOKEN_ENV, "")
    secret = os.environ.get(_SECRET_ENV, "")
    origin = os.environ.get(_ORIGIN_ENV, "")
    if not token or not secret or not origin:
        print("refused: missing operator token, secret, or target origin", file=sys.stderr)
        return 2
    try:
        print(run_identity(ROOT, today=date.today(), token=token, secret=secret, origin=origin))
    except NotApproved:
        print("refused: budget", file=sys.stderr)
        return 1
    except RefusedByChokepoint as exc:
        print(f"refused: {exc.gate}", file=sys.stderr)
        return 1
    except IdentityMismatch:
        print("refused: identity", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
