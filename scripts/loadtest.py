#!/usr/bin/env python3
"""D-13 entry point. Refuses while LIVE_ENABLED is false. Does not flip either switch or edit a cap.

PROVIDER_ENABLED is not required and is not read. A stub-only run still has to pass preflight: identity pin,
Week 1 stub route, the authenticated stub guard, and an explicit 100-case approval. This script does not set
those, does not request /ready, and does not open a socket while the live switch is false.
"""

from __future__ import annotations

import sqlite3
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentforge.evals.loadtest import (  # noqa: E402
    CASES,
    REPORT_FILE,
    LoadTestRefused,
    execute,
    probe_one_chat,
    rate_cap_for,
    report_destination,
    write_report,
)
from agentforge.safety.chokepoint import LIVE_ENABLED  # noqa: E402


def _flag(argv: list[str], name: str) -> str:
    for index, item in enumerate(argv):
        if item == name and index + 1 < len(argv):
            return argv[index + 1]
    return ""


def refusal(argv: list[str], *, live_enabled: bool) -> str | None:
    """None only for an explicit live approval. Does not read PROVIDER_ENABLED.

    --probe is one authenticated chat. It is not the 100-case grant and cannot stand in for it.
    """
    if not live_enabled:
        return "D-13 has no enabled live path"
    if "--probe" in argv:
        if "--live" not in argv or _flag(argv, "--cases") not in ("", "1"):
            return "latency probe is one authenticated chat"
        if not _flag(argv, "--origin") or not _flag(argv, "--pin") or not _flag(argv, "--pid").isdigit() or not _flag(argv, "--revision-dir"):
            return "origin, pin, pid, or revision dir is missing"
        return None
    if "--live" not in argv or _flag(argv, "--cases") != "100":
        return "missing approval for 100 cases"
    if not _flag(argv, "--origin") or not _flag(argv, "--pin") or not _flag(argv, "--pid").isdigit() or not _flag(argv, "--revision-dir"):
        return "origin, pin, pid, or revision dir is missing"
    return None


def offline(argv: list[str]) -> int:
    """Print local pass/fail names. Exits before a socket, including when the live switch is true."""
    import os

    from agentforge.evals.loadtest import offline_preflight
    from agentforge.store.migrate import migrate
    from agentforge.safety.allowlist import Allowlist
    from agentforge.safety.budget import load_caps
    from agentforge.safety.chokepoint import PROVIDER_ENABLED

    if LIVE_ENABLED:
        print("refused: offline preflight refuses while LIVE_ENABLED is true", file=sys.stderr)
        return 2
    store = sqlite3.connect(":memory:")
    try:
        migrate(store)
        store_ready = store.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'exploits'"
        ).fetchone() is not None
    except sqlite3.Error:
        store_ready = False
    finally:
        store.close()
    checks = offline_preflight(
        live_enabled=LIVE_ENABLED,
        provider_enabled=PROVIDER_ENABLED,
        origin=_flag(argv, "--origin"),
        pin=_flag(argv, "--pin"),
        pid=_flag(argv, "--pid"),
        revision_dir=_flag(argv, "--revision-dir"),
        caps=load_caps(ROOT / "config" / "budget.yaml"),
        allowlist=Allowlist.from_file(ROOT / "config" / "allowlist.yaml"),
        secret_set=bool(os.environ.get("AGENTFORGE_BUDGET_SECRET")),
        token_set=bool(os.environ.get("AGENTFORGE_BUDGET_TOKEN")),
        password_set=bool(os.environ.get("COPILOT_FIXTURE_PASSWORD")),
        store_ready=store_ready,
    )
    for name, ok in checks:
        print(f"{name}={'pass' if ok else 'fail'}")
    return 0 if all(ok for _name, ok in checks) else 2


def main(argv: list[str]) -> int:
    """Refuse before a client while the source switch is false. Does not set LIVE_ENABLED."""
    reason = refusal(argv, live_enabled=LIVE_ENABLED)
    if reason:
        print(f"refused: {reason}", file=sys.stderr)
        return 2
    if "--probe" in argv:
        return probe(argv)
    approved = CASES
    origin = _flag(argv, "--origin")
    pin = _flag(argv, "--pin")
    pid = _flag(argv, "--pid")
    revision_dir = _flag(argv, "--revision-dir")
    from agentforge.evals.session import SessionClient, real_transport
    from agentforge.safety.allowlist import Allowlist
    from agentforge.safety.budget import Budget, approval_token, load_caps
    from agentforge.safety.rate import RateCap

    caps = load_caps(ROOT / "config" / "budget.yaml")
    if caps.max_attacks_per_run < CASES:
        print("refused: attack cap is below 100", file=sys.stderr)
        return 2
    budget = Budget(caps)
    secret = __import__("os").environ.get("AGENTFORGE_BUDGET_SECRET", "")
    token = __import__("os").environ.get("AGENTFORGE_BUDGET_TOKEN", "")
    if not secret or token != approval_token(caps, secret):
        print("refused: budget is not approved", file=sys.stderr)
        return 2
    budget.approve(token, secret)
    conn = sqlite3.connect(":memory:")
    from agentforge.store.migrate import MigrateError, migrate

    try:
        migrate(conn)
    except (MigrateError, sqlite3.Error) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        conn.close()
        return 2
    client = SessionClient(
        origin,
        transport=real_transport,
        allowlist=Allowlist.from_file(ROOT / "config" / "allowlist.yaml"),
        budget=budget,
        attestations=[],
        today=date.today(),
        rate_cap=RateCap(rate_cap_for(CASES)),
        chat_reserve_usd=0.0,
        fake_transport=False,
    )
    try:
        report = execute(client, conn, pin=pin, fixture_pid=pid, approved_cases=approved, revision_dir=revision_dir)
    except LoadTestRefused as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    return persist(report, report_destination(ROOT))


def probe(argv: list[str]) -> int:
    """One chat. Prints latency_ms=missing or latency_ms=<number>. Does not write the D-13 report."""
    from agentforge.evals.session import SessionClient, real_transport
    from agentforge.safety.allowlist import Allowlist
    from agentforge.safety.budget import Budget, approval_token, load_caps
    from agentforge.safety.rate import RateCap

    caps = load_caps(ROOT / "config" / "budget.yaml")
    if caps.max_attacks_per_run < 1:
        print("refused: attack cap is below 1", file=sys.stderr)
        return 2
    budget = Budget(caps)
    secret = __import__("os").environ.get("AGENTFORGE_BUDGET_SECRET", "")
    token = __import__("os").environ.get("AGENTFORGE_BUDGET_TOKEN", "")
    if not secret or token != approval_token(caps, secret):
        print("refused: budget is not approved", file=sys.stderr)
        return 2
    budget.approve(token, secret)
    client = SessionClient(
        _flag(argv, "--origin"),
        transport=real_transport,
        allowlist=Allowlist.from_file(ROOT / "config" / "allowlist.yaml"),
        budget=budget,
        attestations=[],
        today=date.today(),
        rate_cap=RateCap(rate_cap_for(1)),
        chat_reserve_usd=0.0,
        fake_transport=False,
    )
    try:
        line = probe_one_chat(
            client,
            pin=_flag(argv, "--pin"),
            fixture_pid=_flag(argv, "--pid"),
            revision_dir=_flag(argv, "--revision-dir"),
        )
    except LoadTestRefused as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    print(line)
    return 0 if line.startswith("latency_ms=") and line != "latency_ms=missing" else 2


def persist(report: object, destination: Path) -> int:
    """Save a returned report, including a mid-run stop. A write failure is named, not a traceback."""
    from agentforge.evals.loadtest import LoadReport, report_problems

    if not isinstance(report, LoadReport):
        print("refused: load test returned no report", file=sys.stderr)
        return 2
    if destination.name != REPORT_FILE.name or destination.parent.name != REPORT_FILE.parent.name:
        print("refused: report path is not the D-13 destination", file=sys.stderr)
        return 2
    try:
        write_report(report, destination)
    except LoadTestRefused as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    print(f"completed={report.cases_completed} live={report.live} report={destination.name}")
    problems = report_problems(report)
    if problems or report.stopped_by is not None:
        detail = ", ".join(problems) if problems else str(report.stopped_by)
        print("report incomplete: " + detail, file=sys.stderr)
        return 2
    return 0 if report.cases_completed == CASES else 2


if __name__ == "__main__":
    args = sys.argv[1:]
    raise SystemExit(offline(args[1:]) if args[:1] == ["--offline-preflight"] else main(args))
