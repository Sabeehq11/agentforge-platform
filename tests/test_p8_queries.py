"""The six observability answers. Offline. No socket, no provider."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from agentforge.observe.queries import answers, categories, cost, ordered_events, pass_fail, resilience, statuses
from agentforge.orchestrator.priority import load_evidence
from agentforge.orchestrator.state import log_run
from agentforge.store.migrate import migrate
from agentforge.store.records import insert_exploit, insert_regression_case, insert_regression_run

PHI = "patient ssn 123-45-6789"
PIN_A = "aaaaaaa"
PIN_B = "bbbbbbb"


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys = ON")
    migrate(conn)
    return conn


def _exploit(conn: sqlite3.Connection, exploit_id: str, category: str, *, status: str = "draft", steps: str = "turn") -> None:
    insert_exploit(
        conn,
        {
            "id": exploit_id,
            "severity": "high",
            "category": category,
            "reproduction_steps": steps,
            "observed_behavior": PHI,
            "expected_behavior": "refuse",
            "system_version": PIN_A,
            "status": status,
        },
    )


def _case(conn: sqlite3.Connection, case_id: str, exploit_id: str, category: str) -> None:
    insert_regression_case(
        conn,
        case_id=case_id,
        exploit_id=exploit_id,
        category=category,
        subcategory=category + "-1",
        invariant_id="canary",
        expected_safe_behavior="refuse",
        system_version=PIN_A,
    )


def _run(conn: sqlite3.Connection, case_id: str, pin: str, outcome: str, repeat: int = 1) -> None:
    insert_regression_run(
        conn,
        case_id=case_id,
        system_version=pin,
        correlation_id="corr-q",
        repeat_index=repeat,
        outcome=outcome,
        invariant_id="canary",
        http_status=200,
        evidence={"note": PHI},
        recorded_at="2026-10-20T00:00:00Z",
    )


def _pins(conn: sqlite3.Connection, *pins: str) -> None:
    conn.execute(
        "INSERT INTO version_baselines (target_pin, recorded_at, identity_checked_at, correlation_id) VALUES (?, ?, ?, ?)",
        (pins[0], "2026-10-20T00:00:02Z", "2026-10-20T00:00:02Z", "corr-q"),
    )
    previous = pins[0]
    for index, pin in enumerate(pins[1:], start=1):
        conn.execute(
            """
            INSERT INTO version_handoffs (target_pin, previous_pin, detected_at, status, correlation_id)
            VALUES (?, ?, ?, 'done', ?)
            """,
            (pin, previous, f"2026-10-20T00:00:0{index}Z", "corr-q"),
        )
        previous = pin
    conn.commit()


def _report(
    conn: sqlite3.Connection,
    exploit_id: str,
    *,
    status: str = "draft",
    remediation: str = "proposed",
    fix_validation: str = "not_run",
    pin: str | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO reports (
            id, exploit_id, correlation_id, body, sequence_hash, status, remediation_status,
            remediation_text, remediation_hash, fix_validation, fix_validation_pin, evidence_run_ids,
            created_at, updated_at
        ) VALUES (?, ?, 'corr-q', ?, ?, ?, ?, 'patch text', ?, ?, ?, '', ?, ?)
        """,
        (
            "rpt-" + exploit_id,
            exploit_id,
            PHI,
            "a" * 64,
            status,
            remediation,
            "b" * 64,
            fix_validation,
            pin,
            "2026-10-20T00:00:00Z",
            "2026-10-20T00:00:00Z",
        ),
    )
    conn.commit()


def test_empty_store_returns_every_question() -> None:
    payload = answers(_conn(), "missing")
    assert [row["category"] for row in payload["categories_tested"]] == [
        "TM-PI", "TM-EX", "TM-SC", "TM-TM", "TM-DS", "TM-ID",
    ]
    assert payload["pass_fail"] == []
    assert payload["resilience"]["trend"] == "inconclusive"
    assert payload["vulnerability_status"] == []
    assert payload["cost"]["scaling"]["scaling"] == "unknown"
    assert payload["agent_order"]["events"] == []


def test_q1_populations_do_not_collapse(tmp_path: Path) -> None:
    conn = _conn()
    authored = tmp_path / "cases"
    authored.mkdir()
    (authored / "only-authored.json").write_text(json.dumps({"category": "TM-PI"}), encoding="utf-8")
    _exploit(conn, "exp-ex", "TM-EX")
    _exploit(conn, "exp-ds", "TM-DS", steps="ds turn")
    _case(conn, "case-ds", "exp-ds", "TM-DS")
    rows = {row["category"]: row for row in categories(conn, authored)}
    assert rows["TM-PI"]["authored_cases"] == 1
    assert rows["TM-PI"]["exploits"] == 0
    assert rows["TM-PI"]["regression_cases"] == 0
    assert rows["TM-PI"]["untested"] is True
    assert rows["TM-EX"]["exploits"] == 1
    assert rows["TM-EX"]["regression_cases"] == 0
    assert rows["TM-DS"]["regression_cases"] == 1
    assert rows["TM-DS"]["tested"] is True
    assert rows["TM-SC"]["untested"] is True
    assert (rows["TM-PI"]["authored_cases"], rows["TM-PI"]["exploits"], rows["TM-PI"]["regression_cases"]) != (
        rows["TM-DS"]["authored_cases"],
        rows["TM-DS"]["exploits"],
        rows["TM-DS"]["regression_cases"],
    )


def test_q2_denominator_keeps_wording_only() -> None:
    conn = _conn()
    _exploit(conn, "exp-1", "TM-PI")
    _case(conn, "case-1", "exp-1", "TM-PI")
    _pins(conn, PIN_A)
    _run(conn, "case-1", PIN_A, "pass", 1)
    _run(conn, "case-1", PIN_A, "fail", 2)
    _run(conn, "case-1", PIN_A, "wording_only", 3)
    row = pass_fail(conn)[0]
    assert row["pass_rate"] == "1/3"
    assert row["fail_rate"] == "1/3"
    assert row["wording_only"] == 1
    assert row["runs"] == 3
    _exploit(conn, "exp-2", "TM-EX", steps="other turn")
    _case(conn, "case-2", "exp-2", "TM-EX")
    empty = [item for item in pass_fail(conn) if item["category"] == "TM-EX"][0]
    assert empty["runs"] == 0
    assert empty["pass_rate"] is None
    assert empty["fail_rate"] is None


def test_q2_displayed_fraction_keeps_the_run_denominator() -> None:
    conn = _conn()
    _exploit(conn, "exp-1", "TM-PI")
    _case(conn, "case-1", "exp-1", "TM-PI")
    _pins(conn, PIN_A)
    _run(conn, "case-1", PIN_A, "wording_only", 1)
    _run(conn, "case-1", PIN_A, "not_exercised", 2)
    _run(conn, "case-1", PIN_A, "fail", 3)
    row = pass_fail(conn)[0]
    assert row["runs"] == 3
    assert row["pass"] == 0
    assert row["fail"] == 1
    assert row["pass_rate"] == "0/3"
    assert row["fail_rate"] == "1/3"


def test_q3_compares_shared_case_ids_only() -> None:
    conn = _conn()
    _exploit(conn, "exp-shared", "TM-PI")
    _exploit(conn, "exp-old", "TM-EX", steps="old turn")
    _exploit(conn, "exp-new", "TM-DS", steps="new turn")
    _case(conn, "shared", "exp-shared", "TM-PI")
    _case(conn, "only-old", "exp-old", "TM-EX")
    _case(conn, "only-new", "exp-new", "TM-DS")
    # Recorded later, but a lexicographic-earlier hash. Order must follow ids, not the clock or the hash.
    conn.execute(
        "INSERT INTO version_baselines (target_pin, recorded_at, identity_checked_at, correlation_id) VALUES (?, ?, ?, ?)",
        (PIN_B, "2026-10-20T00:00:09Z", "2026-10-20T00:00:09Z", "corr-q"),
    )
    conn.execute(
        """
        INSERT INTO version_handoffs (target_pin, previous_pin, detected_at, status, correlation_id)
        VALUES (?, ?, '2026-10-20T00:00:01Z', 'done', 'corr-q')
        """,
        (PIN_A, PIN_B),
    )
    conn.commit()
    _run(conn, "shared", PIN_B, "pass")
    _run(conn, "shared", PIN_A, "fail")
    _run(conn, "only-old", PIN_B, "fail")
    _run(conn, "only-new", PIN_A, "fail")
    result = resilience(conn)
    assert result["pins"] == [PIN_B, PIN_A]
    pair = result["comparisons"][0]
    assert pair["shared_case_ids"] == ["shared"]
    assert pair["coverage_difference"] == {"added": ["only-new"], "removed": ["only-old"]}
    assert pair["trend"] == "less_resilient"
    assert pair["earlier_fail_rate"] == "0/1"
    assert pair["later_fail_rate"] == "1/1"
    assert result["trend"] == "less_resilient"


def test_q3_inconclusive_when_comparison_is_insufficient() -> None:
    one = _conn()
    _pins(one, PIN_A)
    assert resilience(one)["trend"] == "inconclusive"
    disjoint = _conn()
    _exploit(disjoint, "exp-a", "TM-PI")
    _exploit(disjoint, "exp-b", "TM-EX", steps="other")
    _case(disjoint, "case-a", "exp-a", "TM-PI")
    _case(disjoint, "case-b", "exp-b", "TM-EX")
    _pins(disjoint, PIN_A, PIN_B)
    _run(disjoint, "case-a", PIN_A, "fail")
    _run(disjoint, "case-b", PIN_B, "pass")
    pair = resilience(disjoint)["comparisons"][0]
    assert pair["trend"] == "inconclusive"
    assert pair["shared_case_ids"] == []
    assert pair["coverage_difference"]["added"] == ["case-b"]
    no_runs = _conn()
    _pins(no_runs, PIN_A, PIN_B)
    assert resilience(no_runs)["comparisons"][0]["trend"] == "inconclusive"


def test_q4_unmapped_statuses_stay_visible() -> None:
    conn = _conn()
    _exploit(conn, "fixed-only", "TM-PI")
    _case(conn, "case-fixed", "fixed-only", "TM-PI")
    conn.execute("UPDATE regression_cases SET lifecycle = 'fixed' WHERE id = 'case-fixed'")
    _report(conn, "fixed-only", fix_validation="not_run")
    _exploit(conn, "resolved", "TM-EX", steps="resolved turn")
    _case(conn, "case-resolved", "resolved", "TM-EX")
    conn.execute("UPDATE regression_cases SET lifecycle = 'fixed' WHERE id = 'case-resolved'")
    _report(conn, "resolved", fix_validation="fixed", pin=PIN_A)
    _exploit(conn, "regressed-one", "TM-DS", steps="regressed turn")
    _case(conn, "case-regressed", "regressed-one", "TM-DS")
    conn.execute("UPDATE regression_cases SET lifecycle = 'regressed' WHERE id = 'case-regressed'")
    _exploit(conn, "rejected-one", "TM-SC", status="rejected", steps="rejected turn")
    _exploit(conn, "published-one", "TM-TM", steps="published turn")
    conn.execute("UPDATE exploits SET status = 'published' WHERE id = 'published-one'")
    conn.commit()
    mapped = {row["exploit_id"]: row for row in statuses(conn)}
    assert mapped["fixed-only"]["status"] == "proposed"
    assert mapped["fixed-only"]["lifecycle"] == "fixed"
    assert mapped["resolved"]["status"] == "resolved"
    assert mapped["regressed-one"]["status"] == "regressed"
    assert mapped["rejected-one"]["status"] == "rejected"
    assert mapped["published-one"]["status"] == "published"
    assert mapped["published-one"]["exploit_status"] == "published"


def test_output_has_no_phi_or_transcript() -> None:
    conn = _conn()
    _exploit(conn, "exp-phi", "TM-PI", steps=PHI)
    _case(conn, "case-phi", "exp-phi", "TM-PI")
    _pins(conn, PIN_A)
    _run(conn, "case-phi", PIN_A, "fail")
    _report(conn, "exp-phi")
    payload = answers(conn, "corr-q")
    encoded = json.dumps(payload)
    assert PHI not in encoded
    assert "reproduction_steps" not in encoded
    assert "evidence_json" not in encoded
    assert "transcript" not in encoded


def test_orchestrator_can_read_rows() -> None:
    conn = _conn()
    rows = categories(conn, Path("/no/such/cases"))
    assert isinstance(rows, list)
    assert isinstance(rows[0], dict)
    evidence = load_evidence(conn, PIN_A)
    assert isinstance(evidence.coverage, dict)


def test_q6_orders_by_started_at_then_step() -> None:
    conn = _conn()
    log_run(conn, "corr-q", "orchestrator", "done")
    log_run(conn, "corr-q", "documentation", "done")
    conn.execute(
        "UPDATE run_logs SET started_at = '2026-10-20T00:00:02Z' WHERE agent_role = 'orchestrator'"
    )
    conn.execute(
        "UPDATE run_logs SET started_at = '2026-10-20T00:00:01Z' WHERE agent_role = 'documentation'"
    )
    conn.commit()
    events = ordered_events(conn, "corr-q")["events"]
    assert [event["role"] for event in events] == ["documentation", "orchestrator"]
    assert "red_team" not in [event["role"] for event in events]


def test_wording_only_is_not_a_pass_and_regressed_is_not_resolved() -> None:
    conn = _conn()
    _exploit(conn, "exp-1", "TM-PI")
    _case(conn, "case-1", "exp-1", "TM-PI")
    _pins(conn, PIN_A)
    _run(conn, "case-1", PIN_A, "wording_only")
    row = pass_fail(conn)[0]
    assert row["pass"] == 0
    assert row["runs"] == 1
    assert row["pass_rate"] == "0/1"
    assert row["fail_rate"] == "0/1"
    conn.execute("UPDATE regression_cases SET lifecycle = 'regressed'")
    conn.commit()
    assert statuses(conn)[0]["status"] == "regressed"


def _campaign(conn: sqlite3.Connection, correlation_id: str, *, phase: str, attacks: int) -> None:
    conn.execute(
        """
        INSERT INTO campaigns (
            correlation_id, request_json, phase, attacks_done, system_version, created_at, updated_at
        ) VALUES (?, '{}', ?, ?, 'aaaaaaa', ?, ?)
        """,
        (correlation_id, phase, attacks, "2026-10-20T00:00:00Z", "2026-10-20T00:00:00Z"),
    )


def _spend(conn: sqlite3.Connection, correlation_id: str, role: str, incurred: float, reserved: float) -> None:
    call_id = f"{role}-{correlation_id}"
    step = {"red_team": 1, "judge": 2, "target": 3}[role]
    journal_role = {"red_team": "red_team", "judge": "judge", "target": "executor"}[role]
    conn.execute(
        """
        INSERT INTO dispatch_journal (
            correlation_id, step_no, attempt, call_id, role, kind, intent_hash, state, created_at, updated_at
        ) VALUES (?, ?, 0, ?, ?, 'target', ?, 'completed', '2026-10-20T00:00:01Z', '2026-10-20T00:00:01Z')
        """,
        (correlation_id, step, call_id, journal_role, "c" * 64),
    )
    conn.execute(
        """
        INSERT INTO agent_spend (call_id, agent_role, reserved_usd, incurred_usd, state)
        VALUES (?, ?, ?, ?, 'incurred')
        """,
        (call_id, role, reserved, incurred),
    )


def test_cost_splits_roles_and_excludes_reserved() -> None:
    conn = _conn()
    _campaign(conn, "corr-cost", phase="done", attacks=1)
    for role, incurred in (("red_team", 0.10), ("judge", 0.20), ("target", 0.30)):
        _spend(conn, "corr-cost", role, incurred, reserved=0.50)
    log_run(conn, "corr-cost", "orchestrator", "done")
    log_run(conn, "corr-cost", "documentation", "done")
    conn.commit()
    before = conn.execute("SELECT COUNT(*) FROM agent_spend").fetchone()[0]
    found = cost(conn, "corr-cost")
    assert conn.execute("SELECT COUNT(*) FROM agent_spend").fetchone()[0] == before
    by_role = {row["agent_role"]: row for row in found["by_role"]}
    assert [row["agent_role"] for row in found["by_role"]] == ["red_team", "judge", "target", "orchestrator", "documentation"]
    assert by_role["orchestrator"]["incurred_usd"] == 0.0
    assert by_role["documentation"]["source"] == "run_logs"
    assert found["incurred_usd"] == 0.6
    assert found["reserved_usd_not_summed"] == 1.5
    assert found["incurred_usd"] != 2.1
    assert found["scaling"]["scaling"] == "unknown"


def test_scaling_uses_incurred_per_completed_attack() -> None:
    conn = _conn()
    _campaign(conn, "corr-a", phase="done", attacks=2)
    _campaign(conn, "corr-b", phase="done", attacks=2)
    _spend(conn, "corr-a", "target", 0.20, 0.0)
    _spend(conn, "corr-b", "target", 0.40, 0.0)
    conn.commit()
    found = cost(conn, "corr-b")["scaling"]
    assert found["unit"] == "incurred_usd_per_completed_attack"
    assert found["scaling"] == 0.1
    assert found["scaling"] != "unknown"
