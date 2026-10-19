#!/usr/bin/env python3
"""Minimum graded campaign. Makes no call unless LIVE_ENABLED is true.

Does not set LIVE_ENABLED or PROVIDER_ENABLED, and does not read either from the environment. Identity and the
missing-authority case do not require the platform OpenRouter attestation. A chat that can bill the target
requires a fresh provider 'target' attestation. The password and API key are never printed or stored.
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentforge.evals.cases import load_cases  # noqa: E402
from agentforge.local_env import load_local_env  # noqa: E402
from agentforge.evals.executor import CaseResult, merge_results, run_session_case, store_results  # noqa: E402
from agentforge.evals.login import LoginRequest  # noqa: E402
from agentforge.evals.session import SessionClient, real_transport  # noqa: E402
from agentforge.safety.allowlist import Allowlist  # noqa: E402
from agentforge.safety.budget import NotApproved, load_caps  # noqa: E402
from agentforge.safety.chokepoint import TARGET_PROVIDER, RefusedByChokepoint  # noqa: E402
from agentforge.safety.phi import PhiRefused  # noqa: E402
from agentforge.safety.ledger import SHARED_CEILING_USD, Ledger, load_shared_budget  # noqa: E402
from agentforge.safety.operator_approval import OperatorApprovalRefused, load_approvals, require_operator_approval  # noqa: E402
from agentforge.safety.rate import RateCap  # noqa: E402
from agentforge.safety.refusal_log import RefusalLog  # noqa: E402
from agentforge.safety.spend_limits import SpendLimitNotAttested, load_attestations  # noqa: E402
from agentforge.store.migrate import migrate  # noqa: E402

_TOKEN_ENV = "AGENTFORGE_BUDGET_TOKEN"
_SECRET_ENV = "AGENTFORGE_BUDGET_SECRET"
_ORIGIN_ENV = "AGENTFORGE_TARGET_ORIGIN"
_USER_ENV = "AGENTFORGE_FIXTURE_USER"
_PASSWORD_ENV = "AGENTFORGE_FIXTURE_PASSWORD"
_PID_ENV = "AGENTFORGE_FIXTURE_PID"
_CHAT_USD_ENV = "AGENTFORGE_CHAT_RESERVE_USD"
_ORDER = ("seed-tm-ex-3", "seed-tm-ds-1", "seed-tm-pi-1")
_BILLABLE = frozenset({"seed-tm-pi-1"})
_RESULT = ROOT / "evals" / "results" / "campaign-latest.json"


def run_campaign(
    root: Path,
    *,
    today: date,
    token: str,
    secret: str,
    origin: str,
    username: str,
    password: str,
    fixture_pid: str,
    chat_reserve_usd: float | None,
    report_path: Path,
    case_ids: tuple[str, ...] = _ORDER,
) -> tuple[CaseResult, ...]:
    """Selected cases in the fixed order. Fail closed between cases. Billable chat is not implied."""
    unknown = [case_id for case_id in case_ids if case_id not in _ORDER]
    if unknown or len(case_ids) != len(set(case_ids)):
        raise ValueError("campaign selection must be seed-tm-ex-3, seed-tm-ds-1, or seed-tm-pi-1")
    selected = tuple(case_id for case_id in _ORDER if case_id in case_ids)
    billable = any(case_id in _BILLABLE for case_id in selected)
    allowlist = Allowlist.from_file(root / "config" / "allowlist.yaml")
    attestations = load_attestations(root / "config" / "spend_limits.yaml")
    approvals = load_approvals(root / "config" / "operator_approval.yaml")
    if billable:
        require_operator_approval("local-target", approvals, today=today)
        if chat_reserve_usd is None or chat_reserve_usd <= 0 or chat_reserve_usd > 0.25:
            raise ValueError("billable chat reservation must be positive and at most 0.25")
    ledger_path = root / "data" / "agentforge.sqlite3"
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(ledger_path)
    migrate(conn)
    budget = load_shared_budget(conn, load_caps(root / "config" / "budget.yaml"), token, secret)
    ledger = Ledger(conn, budget)
    if billable and chat_reserve_usd is not None and budget.run_spent + chat_reserve_usd > SHARED_CEILING_USD:
        raise ValueError("shared ceiling would be exceeded")
    needs_login = any(case_id != "seed-tm-ex-3" for case_id in selected)
    credentials = LoginRequest(username, password) if needs_login else None
    if needs_login and (not fixture_pid.isdigit() or int(fixture_pid) <= 0):
        raise ValueError("operator fixture pid is missing")
    by_id = {case.case_id: case for case in load_cases(root / "evals" / "cases")}
    missing = [case_id for case_id in _ORDER if case_id not in by_id]
    if missing:
        raise ValueError("campaign case is missing: " + ", ".join(missing))
    client = SessionClient(
        origin,
        transport=real_transport,
        allowlist=allowlist,
        budget=budget,
        attestations=attestations,
        approvals=approvals,
        today=today,
        rate_cap=RateCap(12),
        refusal_log=RefusalLog(root / "evals" / "results" / "refusals.log"),
        chat_reserve_usd=chat_reserve_usd if billable else None,
        fake_transport=False,
        ledger=ledger if billable else None,
    )
    results: list[CaseResult] = []
    for case_id in selected:
        results.append(
            run_session_case(
                by_id[case_id],
                client,
                credentials=None if case_id == "seed-tm-ex-3" else credentials,
                fixture_pid=None if case_id == "seed-tm-ex-3" else fixture_pid,
            )
        )
    stored = merge_results(tuple(results), report_path)
    store_results(stored, report_path)
    return stored


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run selected graded campaign cases.")
    parser.add_argument("--cases", default=",".join(_ORDER), help="comma-separated case ids")
    args = parser.parse_args(argv)
    selected = tuple(part.strip() for part in args.cases.split(",") if part.strip())
    load_local_env(ROOT / ".env")
    required = [_TOKEN_ENV, _SECRET_ENV, _ORIGIN_ENV]
    if any(case_id != "seed-tm-ex-3" for case_id in selected):
        required.extend((_USER_ENV, _PASSWORD_ENV, _PID_ENV))
    if any(case_id in _BILLABLE for case_id in selected):
        required.append(_CHAT_USD_ENV)
    values = {name: os.environ.get(name, "") for name in required}
    if not all(values.values()):
        print("refused: missing operator value for " + ", ".join(name for name, value in values.items() if not value), file=sys.stderr)
        return 2
    reserve = os.environ.get(_CHAT_USD_ENV, "")
    try:
        results = run_campaign(
            ROOT,
            today=date.today(),
            token=values[_TOKEN_ENV],
            secret=values[_SECRET_ENV],
            origin=values[_ORIGIN_ENV],
            username=os.environ.get(_USER_ENV, ""),
            password=os.environ.get(_PASSWORD_ENV, ""),
            fixture_pid=os.environ.get(_PID_ENV, "0"),
            chat_reserve_usd=float(reserve) if reserve else None,
            report_path=_RESULT,
            case_ids=selected,
        )
    except (NotApproved, SpendLimitNotAttested, OperatorApprovalRefused, RefusedByChokepoint, PhiRefused, ValueError) as exc:
        print(f"refused: {type(exc).__name__}", file=sys.stderr)
        return 2
    text = "\n".join(f"{item.case_id} {item.outcome}" for item in results)
    secret = os.environ.get(_PASSWORD_ENV, "")
    if secret and secret in text:
        print("refused: campaign output contained a secret", file=sys.stderr)
        return 2
    print(text)
    expected = {item.category for item in results}
    graded = {item.category for item in results if item.outcome in ("pass", "fail")}
    return 0 if graded == expected else 1


if __name__ == "__main__":
    raise SystemExit(main())
