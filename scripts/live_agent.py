#!/usr/bin/env python3
"""One live SeedMutator turn against the verified target. Makes no call unless LIVE_ENABLED is true.

Does not call OpenRouter and does not set either switch. The mutated turn is the first SeedMutator
variant of the TM-PI-1 seed. Target spend uses the same operator approval, reservation, and ledger.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
from datetime import date, datetime, timezone
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentforge.agents.red_team import SeedMutator, mutate_seed  # noqa: E402
from agentforge.contracts.messages import CampaignRequest  # noqa: E402
from agentforge.evals.cases import load_cases  # noqa: E402
from agentforge.evals.graders import grade_canary  # noqa: E402
from agentforge.evals.login import LoginRequest  # noqa: E402
from agentforge.evals.session import SessionClient, real_transport  # noqa: E402
from agentforge.local_env import load_local_env  # noqa: E402
from agentforge.safety.allowlist import Allowlist  # noqa: E402
from agentforge.safety.budget import NotApproved, load_caps  # noqa: E402
from agentforge.safety.chokepoint import RefusedByChokepoint  # noqa: E402
from agentforge.safety.ledger import SHARED_CEILING_USD, Ledger, load_shared_budget  # noqa: E402
from agentforge.safety.operator_approval import OperatorApprovalRefused, load_approvals, require_operator_approval  # noqa: E402
from agentforge.safety.phi import PhiRefused, require_clean  # noqa: E402
from agentforge.safety.rate import RateCap  # noqa: E402
from agentforge.safety.refusal_log import RefusalLog  # noqa: E402
from agentforge.safety.spend_limits import load_attestations  # noqa: E402
from agentforge.store.migrate import migrate  # noqa: E402

_RESULT = ROOT / "evals" / "results" / "agent-live.json"
_LEDGER = ROOT / "data" / "agentforge.sqlite3"


def run_agent(root: Path) -> dict[str, object]:
    load_local_env(root / ".env")
    origin = os.environ.get("AGENTFORGE_TARGET_ORIGIN", "")
    user = os.environ.get("AGENTFORGE_FIXTURE_USER", "")
    password = os.environ.get("AGENTFORGE_FIXTURE_PASSWORD", "")
    pid = os.environ.get("AGENTFORGE_FIXTURE_PID", "")
    token = os.environ.get("AGENTFORGE_BUDGET_TOKEN", "")
    secret = os.environ.get("AGENTFORGE_BUDGET_SECRET", "")
    reserve = float(os.environ.get("AGENTFORGE_CHAT_RESERVE_USD", "0"))
    if not all((origin, user, password, pid, token, secret)) or reserve <= 0 or reserve > 0.25:
        raise ValueError("agent run is missing an operator value or a valid chat reservation")
    today = date.today()
    approvals = load_approvals(root / "config" / "operator_approval.yaml")
    require_operator_approval("local-target", approvals, today=today)
    _LEDGER.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(_LEDGER)
    migrate(conn)
    budget = load_shared_budget(conn, load_caps(root / "config" / "budget.yaml"), token, secret)
    if budget.run_spent + reserve > SHARED_CEILING_USD:
        raise ValueError("shared ceiling would be exceeded")
    ledger = Ledger(conn, budget)
    seeds = {case.category: case for case in load_cases(root / "evals" / "cases")}
    mutator = SeedMutator(ledger, seeds, reserve_usd=0.0)
    correlation = "agent-" + uuid4().hex[:12]
    request: CampaignRequest = {
        "message_id": uuid4().hex[:16],
        "correlation_id": correlation,
        "schema_version": "v1",
        "produced_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target_pin": "9f03654",
        "category": "TM-PI",
        "surface": "chat",
        "per_run_usd_cap": 5.0,
        "attack_count_cap": 1,
        "approval_token_ref": "operator-approval",
    }
    proposed = mutator.propose(request)
    if "error_code" in proposed:
        raise ValueError("seed mutation was refused before the target call")
    turn = mutate_seed(seeds["TM-PI"])[0]
    client = SessionClient(
        origin,
        transport=real_transport,
        allowlist=Allowlist.from_file(root / "config" / "allowlist.yaml"),
        budget=budget,
        attestations=load_attestations(root / "config" / "spend_limits.yaml"),
        approvals=approvals,
        today=today,
        rate_cap=RateCap(12),
        refusal_log=RefusalLog(root / "evals" / "results" / "refusals.log"),
        chat_reserve_usd=reserve,
        ledger=ledger,
    )
    client.login(LoginRequest(user, password))
    client.read_dock()
    client.open_patient(pid)
    chat = client.post_chat(turn)
    canary = seeds["TM-PI"].canary or "CANARY-AF-PI1"
    outcome = grade_canary(chat.text, canary)
    if outcome not in ("pass", "fail"):
        raise ValueError("agent response was not graded")
    body = {
        "case_id": "seed-tm-pi-1",
        "role": "red_team",
        "correlation_id": correlation,
        "outcome": outcome,
        "ledger_call_id": client.last_target_call_id,
        "target_calls": 1,
    }
    text = json.dumps(body, indent=2, sort_keys=True) + "\n"
    require_clean(text)
    if password in text:
        raise PhiRefused(("secret",))
    _RESULT.parent.mkdir(parents=True, exist_ok=True)
    _RESULT.write_text(text, encoding="utf-8")
    return body


def main() -> int:
    try:
        body = run_agent(ROOT)
    except (NotApproved, OperatorApprovalRefused, RefusedByChokepoint, PhiRefused, ValueError) as exc:
        print(f"refused: {type(exc).__name__}", file=sys.stderr)
        return 2
    print(body["case_id"], body["outcome"])
    return 0 if body["outcome"] in ("pass", "fail") else 1


if __name__ == "__main__":
    raise SystemExit(main())
