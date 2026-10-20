"""Queryable answers for the six PRD observability questions.

Read only. Counts, statuses, hashes and costs. Never reproduction steps, transcripts or evidence bodies.
Authored cases, exploit rows and regression cases are three populations and are never summed together.

Status map (Q4), applied in this order so a store value is not folded into a PRD word:

- rejected: exploit or report status is rejected
- regressed: case lifecycle or report fix_validation is regressed
- resolved: case lifecycle is fixed and report fix_validation is fixed (both required)
- in_progress: exploit or report is pending_approval, or remediation is pending_authorization
- published: exploit or report is published without fix_validation fixed
- proposed: remediation is proposed and the finding is otherwise open
- open: exploit is draft, or the case lifecycle is open, or there is no case yet
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

CATEGORIES = ("TM-PI", "TM-EX", "TM-SC", "TM-TM", "TM-DS", "TM-ID")
PAID_ROLES = ("red_team", "judge", "target")
UNPAID_ROLES = ("orchestrator", "documentation")
ROLES = PAID_ROLES + UNPAID_ROLES
FORBIDDEN = frozenset({"reproduction_steps", "transcript", "transcript_json", "evidence_json", "body", "turns_json"})
CASES = Path(__file__).resolve().parents[3] / "evals" / "cases"


def categories(conn: sqlite3.Connection, cases_dir: Path = CASES) -> list[dict[str, Any]]:
    """Q1. Authored files, exploit rows and regression cases, per category. Untested is not omitted."""
    authored = _authored(cases_dir)
    exploits = _counts(conn, "SELECT category, COUNT(*) FROM exploits GROUP BY category")
    cases = _counts(conn, "SELECT category, COUNT(*) FROM regression_cases GROUP BY category")
    rows = []
    for category in CATEGORIES:
        regression_cases = cases.get(category, 0)
        rows.append(
            {
                "category": category,
                "authored_cases": authored.get(category, 0),
                "exploits": exploits.get(category, 0),
                "regression_cases": regression_cases,
                "untested": regression_cases == 0,
                "tested": regression_cases > 0,
            }
        )
    return rows


def pass_fail(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Q2. Rates over every regression_runs row. wording_only and not_exercised stay in the denominator."""
    groups = _run_groups(conn)
    counts = {
        (str(row[0]), str(row[1]), str(row[2])): int(row[3])
        for row in conn.execute(
            """
            SELECT c.category, r.system_version, r.outcome, COUNT(*)
            FROM regression_runs r
            JOIN regression_cases c ON c.id = r.case_id
            GROUP BY c.category, r.system_version, r.outcome
            """
        )
    }
    rows = []
    for category, version in groups:
        bucket = {name: counts.get((category, version, name), 0) for name in ("pass", "fail", "wording_only", "not_exercised")}
        runs = sum(bucket.values())
        rows.append(
            {
                "category": category,
                "system_version": version,
                "population": "regression_runs",
                "runs": runs,
                "pass": bucket["pass"],
                "fail": bucket["fail"],
                "wording_only": bucket["wording_only"],
                "not_exercised": bucket["not_exercised"],
                "pass_rate": None if runs == 0 else _fraction(bucket["pass"], runs),
                "fail_rate": None if runs == 0 else _fraction(bucket["fail"], runs),
            }
        )
    return rows


def resilience(conn: sqlite3.Connection) -> dict[str, Any]:
    """Q3. Adjacent recorded pins, compared only on case ids that ran on both. Coverage gaps are separate."""
    pins = _recorded_pins(conn)
    comparisons = []
    for earlier, later in zip(pins, pins[1:], strict=False):
        left = _cases_on_pin(conn, earlier)
        right = _cases_on_pin(conn, later)
        shared = sorted(left & right)
        pair: dict[str, Any] = {
            "earlier": earlier,
            "later": later,
            "shared_case_ids": shared,
            "coverage_difference": {"added": sorted(right - left), "removed": sorted(left - right)},
        }
        if not shared:
            pair["trend"] = "inconclusive"
            pair["earlier_fail_rate"] = None
            pair["later_fail_rate"] = None
        else:
            earlier_rate = _fail_rate(conn, earlier, shared)
            later_rate = _fail_rate(conn, later, shared)
            pair["earlier_fail_rate"] = earlier_rate[0]
            pair["later_fail_rate"] = later_rate[0]
            pair["trend"] = _trend(earlier_rate[1], later_rate[1])
        comparisons.append(pair)
    trend = "inconclusive"
    if comparisons and all(item["trend"] != "inconclusive" for item in comparisons):
        trend = str(comparisons[-1]["trend"])
    return {
        "population": "shared_regression_case_ids",
        "pins": pins,
        "comparisons": comparisons,
        "trend": trend,
    }


def statuses(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Q4. One row per exploit. Mapped status plus the source fields, so a store value stays visible."""
    rows = []
    for exploit in conn.execute(
        "SELECT id, status, category, severity FROM exploits ORDER BY id"
    ):
        exploit_id, exploit_status, category, severity = (str(exploit[0]), str(exploit[1]), str(exploit[2]), str(exploit[3]))
        case = conn.execute(
            "SELECT id, lifecycle FROM regression_cases WHERE exploit_id = ?",
            (exploit_id,),
        ).fetchone()
        report = conn.execute(
            """
            SELECT status, remediation_status, fix_validation, fix_validation_pin
            FROM reports WHERE exploit_id = ?
            """,
            (exploit_id,),
        ).fetchone()
        lifecycle = None if case is None else str(case[1])
        report_status = None if report is None else str(report[0])
        remediation = None if report is None else str(report[1])
        fix_validation = None if report is None else str(report[2])
        pin = None if report is None or report[3] is None else str(report[3])
        rows.append(
            {
                "exploit_id": exploit_id,
                "category": category,
                "severity": severity,
                "status": _map_status(exploit_status, lifecycle, report_status, remediation, fix_validation),
                "exploit_status": exploit_status,
                "lifecycle": lifecycle,
                "report_status": report_status,
                "remediation_status": remediation,
                "fix_validation": fix_validation,
                "fix_validation_pin": pin,
            }
        )
    return rows


def cost(conn: sqlite3.Connection, correlation_id: str) -> dict[str, Any]:
    """Q5. Incurred USD by role for one run. Reserved is not added. Scaling needs two completed campaigns."""
    incurred = {role: 0.0 for role in PAID_ROLES}
    reserved = {role: 0.0 for role in PAID_ROLES}
    for role, incurred_usd, reserved_usd in conn.execute(
        """
        SELECT s.agent_role, s.incurred_usd, s.reserved_usd
        FROM agent_spend s
        JOIN dispatch_journal j ON j.call_id = s.call_id
        WHERE j.correlation_id = ? AND s.state = 'incurred'
        """,
        (correlation_id,),
    ):
        incurred[str(role)] = incurred.get(str(role), 0.0) + float(incurred_usd)
        reserved[str(role)] = reserved.get(str(role), 0.0) + float(reserved_usd)
    present = {
        str(row[0])
        for row in conn.execute("SELECT agent_role FROM run_logs WHERE correlation_id = ?", (correlation_id,))
    }
    by_role = []
    for role in ROLES:
        if role in PAID_ROLES:
            by_role.append({"agent_role": role, "incurred_usd": round(incurred[role], 6), "source": "agent_spend"})
        elif role in present:
            by_role.append({"agent_role": role, "incurred_usd": 0.0, "source": "run_logs"})
        else:
            by_role.append({"agent_role": role, "incurred_usd": 0.0, "source": "absent"})
    total = round(sum(incurred.values()), 6)
    return {
        "correlation_id": correlation_id,
        "population": "incurred_usd",
        "by_role": by_role,
        "incurred_usd": total,
        "reserved_excluded": True,
        "reserved_usd_not_summed": round(sum(reserved.values()), 6),
        "scaling": _scaling(conn),
    }


def ordered_events(conn: sqlite3.Connection, correlation_id: str) -> dict[str, Any]:
    """Q6. What each agent did, in started_at order, then journal step. Omits a role with no row."""
    from agentforge.orchestrator.trace import trace_agents

    agents = trace_agents(conn, correlation_id)
    events: list[dict[str, Any]] = []
    for row in conn.execute(
        """
        SELECT agent_role, state, error_code, started_at, id
        FROM run_logs WHERE correlation_id = ? ORDER BY started_at, id
        """,
        (correlation_id,),
    ):
        events.append(
            {
                "kind": "run_log",
                "role": str(row[0]),
                "state": str(row[1]),
                "error_code": row[2],
                "started_at": str(row[3]),
                "step": int(row[4]),
            }
        )
    for row in conn.execute(
        """
        SELECT role, kind, state, step_no, created_at
        FROM dispatch_journal WHERE correlation_id = ? ORDER BY step_no, id
        """,
        (correlation_id,),
    ):
        events.append(
            {
                "kind": "journal",
                "role": str(row[0]),
                "journal_kind": str(row[1]),
                "state": str(row[2]),
                "started_at": str(row[4]),
                "step": int(row[3]),
            }
        )
    events.sort(key=lambda item: (item["started_at"], item["step"], item["kind"]))
    return {
        "correlation_id": correlation_id,
        "agents": list(agents["agents"]),
        "executor": agents["executor"],
        "events": events,
    }


def answers(conn: sqlite3.Connection, correlation_id: str | None = None, cases_dir: Path = CASES) -> dict[str, Any]:
    """All six answers. Plain rows, so the Orchestrator can read the same functions."""
    cid = correlation_id or ""
    payload = {
        "categories_tested": categories(conn, cases_dir),
        "pass_fail": pass_fail(conn),
        "resilience": resilience(conn),
        "vulnerability_status": statuses(conn),
        "cost": cost(conn, cid),
        "agent_order": ordered_events(conn, cid),
    }
    _reject_forbidden(payload)
    return payload


def _authored(cases_dir: Path) -> dict[str, int]:
    counts = {category: 0 for category in CATEGORIES}
    if not cases_dir.is_dir():
        return counts
    for path in sorted(cases_dir.glob("*.json")):
        raw = json.loads(path.read_text(encoding="utf-8"))
        category = str(raw.get("category", ""))
        if category in counts:
            counts[category] += 1
    return counts


def _counts(conn: sqlite3.Connection, sql: str) -> dict[str, int]:
    return {str(row[0]): int(row[1]) for row in conn.execute(sql)}


def _run_groups(conn: sqlite3.Connection) -> list[tuple[str, str]]:
    pins = _recorded_pins(conn)
    categories_present = [str(row[0]) for row in conn.execute("SELECT DISTINCT category FROM regression_cases ORDER BY category")]
    groups = [(category, pin) for category in categories_present for pin in pins]
    seen = set(groups)
    for row in conn.execute(
        """
        SELECT DISTINCT c.category, r.system_version
        FROM regression_runs r JOIN regression_cases c ON c.id = r.case_id
        """
    ):
        key = (str(row[0]), str(row[1]))
        if key not in seen:
            groups.append(key)
            seen.add(key)
    return groups


def _recorded_pins(conn: sqlite3.Connection) -> list[str]:
    pins = [str(row[0]) for row in conn.execute("SELECT target_pin FROM version_baselines ORDER BY id")]
    pins.extend(str(row[0]) for row in conn.execute("SELECT target_pin FROM version_handoffs ORDER BY id"))
    return pins


def _cases_on_pin(conn: sqlite3.Connection, pin: str) -> set[str]:
    return {
        str(row[0])
        for row in conn.execute(
            "SELECT DISTINCT case_id FROM regression_runs WHERE system_version = ?",
            (pin,),
        )
    }


def _fail_rate(conn: sqlite3.Connection, pin: str, case_ids: list[str]) -> tuple[str, tuple[int, int]]:
    wanted = set(case_ids)
    rows = conn.execute(
        "SELECT case_id, outcome FROM regression_runs WHERE system_version = ?",
        (pin,),
    ).fetchall()
    bucket: dict[str, int] = {}
    for case_id, outcome in rows:
        if str(case_id) not in wanted:
            continue
        name = str(outcome)
        bucket[name] = bucket.get(name, 0) + 1
    runs = sum(bucket.values())
    fails = bucket.get("fail", 0)
    if runs == 0:
        return ("0/0", (0, 0))
    return (_fraction(fails, runs), (fails, runs))


def _trend(earlier: tuple[int, int], later: tuple[int, int]) -> str:
    if earlier[1] == 0 or later[1] == 0:
        return "inconclusive"
    earlier_rate = earlier[0] / earlier[1]
    later_rate = later[0] / later[1]
    if later_rate < earlier_rate:
        return "more_resilient"
    if later_rate > earlier_rate:
        return "less_resilient"
    return "unchanged"


def _map_status(
    exploit_status: str,
    lifecycle: str | None,
    report_status: str | None,
    remediation: str | None,
    fix_validation: str | None,
) -> str:
    if exploit_status == "rejected" or report_status == "rejected":
        return "rejected"
    if lifecycle == "regressed" or fix_validation == "regressed":
        return "regressed"
    if lifecycle == "fixed" and fix_validation == "fixed":
        return "resolved"
    if exploit_status == "pending_approval" or report_status == "pending_approval" or remediation == "pending_authorization":
        return "in_progress"
    if (exploit_status == "published" or report_status == "published") and fix_validation != "fixed":
        return "published"
    if remediation == "proposed" and exploit_status == "draft" and report_status != "pending_approval":
        return "proposed"
    if lifecycle is None or exploit_status == "draft" or lifecycle == "open":
        return "open"
    return exploit_status


def _scaling(conn: sqlite3.Connection) -> dict[str, Any]:
    done = conn.execute(
        """
        SELECT correlation_id, attacks_done FROM campaigns
        WHERE phase = 'done' ORDER BY created_at, correlation_id
        """
    ).fetchall()
    unit = "incurred_usd_per_completed_attack"
    if len(done) < 2:
        return {"unit": unit, "scaling": "unknown", "campaigns": len(done)}
    rates = []
    for correlation_id, attacks in done:
        spent = conn.execute(
            """
            SELECT COALESCE(SUM(s.incurred_usd), 0)
            FROM agent_spend s JOIN dispatch_journal j ON j.call_id = s.call_id
            WHERE j.correlation_id = ? AND s.state = 'incurred'
            """,
            (correlation_id,),
        ).fetchone()
        count = int(attacks)
        rates.append(None if count == 0 else float(spent[0]) / count)
    earlier, later = rates[-2], rates[-1]
    if earlier is None or later is None:
        return {"unit": unit, "scaling": "unknown", "campaigns": len(done)}
    return {
        "unit": unit,
        "scaling": round(later - earlier, 6),
        "earlier_usd_per_attack": round(earlier, 6),
        "later_usd_per_attack": round(later, 6),
        "campaigns": len(done),
    }


def _fraction(numerator: int, denominator: int) -> str:
    """Show numerator/runs. Do not cancel, including a zero numerator: 0/3 is not 0/1."""
    return f"{numerator}/{denominator}"


def _reject_forbidden(value: Any) -> None:
    if isinstance(value, dict):
        found = FORBIDDEN.intersection(value)
        if found:
            raise RuntimeError("observability output included " + ", ".join(sorted(found)))
        for item in value.values():
            _reject_forbidden(item)
    elif isinstance(value, list):
        for item in value:
            _reject_forbidden(item)
