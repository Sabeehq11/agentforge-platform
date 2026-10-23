#!/usr/bin/env python3
"""Minimum graded campaign. Makes no call unless the gitignored runtime opt-in is present.

Does not read LIVE_ENABLED from the environment and does not set the committed switches. Identity and the
missing-authority case do not require the platform OpenRouter attestation. A chat that can bill the target
requires a fresh provider 'target' attestation. On the isolated loopback port, a verified stub ready body
stays zero-cost. A verified OpenRouter ready body uses the existing local-target approval and the operator's
chat reservation, at most $0.25. The password and API key are never printed or stored.
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from collections.abc import Callable
from datetime import date
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentforge.evals.cases import load_cases  # noqa: E402
from agentforge.local_env import load_local_env  # noqa: E402
from agentforge.evals.executor import CaseResult, merge_results, run_session_case, store_results  # noqa: E402
from agentforge.evals.session import SessionClient, real_transport, stub_ready  # noqa: E402
from agentforge.safety.operator_approval import (  # noqa: E402
    OperatorApprovalRefused,
    load_approvals,
    require_operator_approval,
    require_public_target,
)
from agentforge.safety.allowlist import Allowlist, Entry  # noqa: E402
from agentforge.safety.budget import NotApproved, load_caps  # noqa: E402
from agentforge.safety.chokepoint import TARGET_PROVIDER, RefusedByChokepoint, apply_runtime_opt_in  # noqa: E402
from agentforge.safety.phi import PhiRefused  # noqa: E402
from agentforge.safety.ledger import SHARED_CEILING_USD, Ledger, load_shared_budget  # noqa: E402
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
_ORDER = ("seed-tm-ex-3", "seed-tm-ds-1", "seed-tm-pi-1", "seed-tm-tm-1")
_BILLABLE = frozenset({"seed-tm-pi-1", "seed-tm-tm-1"})
_TM_RESERVE_USD = 0.05
_RESULT = ROOT / "evals" / "results" / "campaign-latest.json"
_ISOLATED_ORIGIN = "https://127.0.0.1:19300"
_AGENT_READY = ("127.0.0.1", 18400, "/ready")
_OPENROUTER_READY = "HTTP 200"
_RESERVE_MAX_USD = 0.25


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
    ready_reader: Callable[[], tuple[int, bytes]] | None = None,
) -> tuple[CaseResult, ...]:
    """Selected cases in the fixed order. Fail closed between cases. Billable chat is not implied."""
    unknown = [case_id for case_id in case_ids if case_id not in _ORDER]
    if unknown or len(case_ids) != len(set(case_ids)):
        raise ValueError("campaign selection must be seed-tm-ex-3, seed-tm-ds-1, seed-tm-pi-1, or seed-tm-tm-1")
    selected = tuple(case_id for case_id in _ORDER if case_id in case_ids)
    isolated = _isolated_loopback(origin)
    public = _public_origin(origin)
    route = _agent_route(ready_reader) if (isolated or public) and _has_billable(selected) else None
    if public and _has_billable(selected) and route != "stub":
        raise ValueError("public-target seed requires a verified stub")
    billable = _reserve_required(origin, selected, route)
    allowlist = _allowlist(root, origin)
    attestations = load_attestations(root / "config" / "spend_limits.yaml")
    approvals = load_approvals(root / "config" / "operator_approval.yaml")
    if public and _has_billable(selected):
        require_public_target(approvals, origin=origin, today=today)
    if billable:
        require_operator_approval("local-target", approvals, today=today)
        if not _reservation_allowed(selected, chat_reserve_usd):
            raise ValueError("billable chat reservation is outside the case cap")
    ledger_path = root / "data" / "agentforge.sqlite3"
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(ledger_path)
    migrate(conn)
    budget = load_shared_budget(conn, load_caps(root / "config" / "budget.yaml"), token, secret)
    ledger = Ledger(conn, budget)
    if billable and chat_reserve_usd is not None and budget.run_spent + chat_reserve_usd > SHARED_CEILING_USD:
        raise ValueError("shared ceiling would be exceeded")
    needs_login = any(case_id != "seed-tm-ex-3" for case_id in selected)
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
        rate_cap=RateCap(12 * len(selected)),
        refusal_log=RefusalLog(root / "evals" / "results" / "refusals.log"),
        chat_reserve_usd=chat_reserve_usd if billable else 0.0 if route == "stub" else None,
        fake_transport=False,
        # The executor refuses a positive client-ledger reservation before chat. A verified stub,
        # public or isolated, carries no ledger. An isolated OpenRouter chat reserves on the shared
        # budget instead. Any other billable path keeps its ledger.
        ledger=None if isolated or route == "stub" else ledger if billable else None,
        fixture_username=username if needs_login else None,
        fixture_password=password if needs_login else None,
    )
    if route == "stub":
        client.accept_authenticated_stub_guard()
    results: list[CaseResult] = []
    for case_id in selected:
        results.append(
            run_session_case(
                by_id[case_id],
                client,
                credentials=None,
                fixture_pid=None if case_id == "seed-tm-ex-3" else fixture_pid,
            )
        )
    stored = merge_results(tuple(results), report_path)
    store_results(stored, report_path)
    return tuple(results)


def _public_origin(origin: str) -> bool:
    """An https host that is not the isolated loopback. The tunnel is this path."""
    parts = urlsplit(origin.rstrip("/"))
    return (
        parts.scheme == "https"
        and bool(parts.hostname)
        and parts.hostname not in {"127.0.0.1", "localhost", "::1"}
        and parts.path in {"", "/"}
    )


def _isolated_loopback(origin: str) -> bool:
    """The isolated R7 HTTPS port only. A tunnel hostname is not this path."""
    parts = urlsplit(origin.rstrip("/"))
    return parts.scheme == "https" and parts.hostname == "127.0.0.1" and parts.port == 19300 and parts.path in {"", "/"}


def _allowlist(root: Path, origin: str) -> Allowlist:
    """Reviewed entries, plus the isolated loopback port when that origin was requested.

    The tracked allowlist keeps 127.0.0.1:8300. The overlay cannot name a loopback host, so this process adds
    only the isolated port and does not rewrite either file.
    """
    listed = Allowlist.from_file(root / "config" / "allowlist.yaml", local=root / "config" / "allowlist.local.yaml")
    if not _isolated_loopback(origin):
        return listed
    return Allowlist((*listed.entries, Entry("https", "127.0.0.1", 19300, "/")))


def _has_billable(case_ids: tuple[str, ...]) -> bool:
    return any(case_id in _BILLABLE for case_id in case_ids)


def _reservation_allowed(case_ids: tuple[str, ...], chat_reserve_usd: float | None) -> bool:
    """seed-tm-tm-1 reserves exactly $0.05. Another billable case keeps the existing $0.25 ceiling."""
    if chat_reserve_usd is None or chat_reserve_usd <= 0:
        return False
    if "seed-tm-tm-1" in case_ids:
        return chat_reserve_usd == _TM_RESERVE_USD
    return chat_reserve_usd <= _RESERVE_MAX_USD


def _reserve_required(origin: str, case_ids: tuple[str, ...], route: str | None) -> bool:
    """A billable case needs the $0.25 reservation unless the isolated agent is the verified stub."""
    if not _has_billable(case_ids):
        return False
    if _isolated_loopback(origin):
        return route == "openrouter"
    if _public_origin(origin):
        return False
    return True


def _agent_route(reader: Callable[[], tuple[int, bytes]] | None = None) -> str:
    """stub or openrouter from the isolated agent's ready body. Anything else fails closed."""
    status, body = _read_agent_ready() if reader is None else reader()
    return _route_from_ready(status, body)


def _read_agent_ready() -> tuple[int, bytes]:
    """GET the isolated agent's loopback /ready. Not the public tunnel and not the module."""
    from http.client import HTTPConnection

    host, port, path = _AGENT_READY
    conn = HTTPConnection(host, port, timeout=5)
    try:
        conn.request("GET", path)
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


def _route_from_ready(status: int, body: bytes) -> str:
    """The stub sentence is free. HTTP 200 from the provider check is the OpenRouter route."""
    if status != 200:
        raise ValueError("isolated agent ready check failed")
    verdict = stub_ready(body)
    if verdict is True:
        return "stub"
    if verdict is False and _provider_detail(body) == _OPENROUTER_READY:
        return "openrouter"
    raise ValueError("isolated agent is not a verified stub or OpenRouter route")


def _provider_detail(body: bytes) -> str:
    import json

    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("isolated agent ready body is not JSON") from exc
    checks = payload.get("checks") if isinstance(payload, dict) else None
    provider = checks.get("llm_provider") if isinstance(checks, dict) else None
    detail = provider.get("detail") if isinstance(provider, dict) else None
    if not isinstance(detail, str):
        raise ValueError("isolated agent ready body has no provider detail")
    return detail


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run selected graded campaign cases.")
    parser.add_argument("--cases", default=",".join(_ORDER), help="comma-separated case ids")
    args = parser.parse_args(argv)
    selected = tuple(part.strip() for part in args.cases.split(",") if part.strip())
    if not apply_runtime_opt_in(path=ROOT / "config" / "live.local"):
        print("refused: LIVE_ENABLED is false. No network call was made.", file=sys.stderr)
        return 2
    load_local_env(ROOT / ".env", override=frozenset({_ORIGIN_ENV}))
    required = [_TOKEN_ENV, _SECRET_ENV, _ORIGIN_ENV]
    if any(case_id != "seed-tm-ex-3" for case_id in selected):
        required.extend((_USER_ENV, _PASSWORD_ENV, _PID_ENV))
    values = {name: os.environ.get(name, "") for name in required}
    origin = values.get(_ORIGIN_ENV, "")
    public = _public_origin(origin)
    route = _agent_route() if _has_billable(selected) and (_isolated_loopback(origin) or public) else None
    if public and _has_billable(selected) and route != "stub":
        print("refused: public-target seed requires a verified stub", file=sys.stderr)
        return 2
    if _reserve_required(origin, selected, route):
        required.append(_CHAT_USD_ENV)
        values[_CHAT_USD_ENV] = os.environ.get(_CHAT_USD_ENV, "")
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
