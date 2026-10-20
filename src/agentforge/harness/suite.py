"""Claim a version handoff and replay regression cases on the stub.

An interrupted claim resumes under the same correlation id. Committed repeats are not executed
again. This replay rule is stub-only: a live call must use the dispatch journal and must not copy it.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from agentforge.contracts.messages import ErrorEnvelope
from agentforge.contracts.validate import validate
from agentforge.agents.documentation import fix_validation_line, write_report_markdown
from agentforge.harness.invariants import evidence_of, grade
from agentforge.harness.stub_target import StubTarget
from agentforge.orchestrator.state import halt, log_run, now_iso
from agentforge.store.access import issue_grant
from agentforge.store.records import insert_regression_run, outcomes

REPEATS = 3


class SuiteKill(Exception):
    """A test hook. Raised after a named point has committed, so resume can continue."""

    def __init__(self, point: str) -> None:
        self.point = point
        super().__init__(point)


@dataclass
class SuiteResult:
    correlation_id: str
    target_pin: str
    status: str  # done | not_owner | already_done | regression_detected | predecessor_invalid
    cases: int = 0
    detections: list[ErrorEnvelope] = field(default_factory=list)


def claim_handoff(conn: sqlite3.Connection, handoff_id: int, correlation_id: str) -> str:
    """Compare-and-swap pending to claimed. Returns claimed, not_owner, already_done or missing."""
    row = conn.execute("SELECT status, claimed_by FROM version_handoffs WHERE id = ?", (handoff_id,)).fetchone()
    if row is None:
        return "missing"
    status, owner = str(row[0]), row[1]
    if status == "done":
        return "already_done"
    if status == "claimed":
        return "claimed" if owner == correlation_id else "not_owner"
    older = conn.execute(
        "SELECT 1 FROM regression_jobs WHERE status IN ('pending', 'claimed') AND handoff_id < ? LIMIT 1",
        (handoff_id,),
    ).fetchone()
    if older is not None:
        return "not_owner"
    try:
        with conn:
            cursor = conn.execute(
                """
                UPDATE version_handoffs SET status = 'claimed', claimed_by = ?
                WHERE id = ? AND status = 'pending' AND claimed_by IS NULL
                """,
                (correlation_id, handoff_id),
            )
            if cursor.rowcount != 1:
                raise sqlite3.IntegrityError("claim missed")
            job = conn.execute(
                "UPDATE regression_jobs SET status = 'claimed', claimed_by = ? WHERE handoff_id = ? AND status = 'pending'",
                (correlation_id, handoff_id),
            )
            if job.rowcount != 1:
                raise sqlite3.IntegrityError("job claim missed")
    except sqlite3.IntegrityError:
        return "not_owner"
    return "claimed"


def run_suite(
    conn: sqlite3.Connection,
    handoff_id: int,
    correlation_id: str,
    stub: StubTarget,
    *,
    kill_at: str | None = None,
    kill_after_calls: int | None = None,
    reports_dir: Path | None = None,
) -> SuiteResult:
    """Replay every case against the stub pin. Resume skips committed repeats and does not re-detect."""
    row = conn.execute(
        "SELECT target_pin, previous_pin, status, claimed_by FROM version_handoffs WHERE id = ?",
        (handoff_id,),
    ).fetchone()
    if row is None:
        return SuiteResult(correlation_id, "", "missing")
    target_pin, previous_pin, status, owner = str(row[0]), str(row[1]), str(row[2]), row[3]
    if status == "done":
        return SuiteResult(correlation_id, target_pin, "already_done", detections=_stored(conn, target_pin, correlation_id))
    if status != "claimed" or owner != correlation_id:
        return SuiteResult(correlation_id, target_pin, "not_owner")
    if not predecessor_valid(conn, handoff_id):
        # Do not grade against a pin that is not the recorded predecessor. Leave the claim so the owner can resume
        # after the chain is repaired. No run, cache, detection, or done write.
        return SuiteResult(correlation_id, target_pin, "predecessor_invalid")
    log_run(conn, correlation_id, "harness", "running")
    _maybe_kill(kill_at, "before_runs")
    cases = conn.execute(
        "SELECT id, category, subcategory, invariant_id, expected_safe_behavior, exploit_id FROM regression_cases ORDER BY id"
    ).fetchall()
    for case_id, _category, subcategory, _invariant, expected, _exploit_id in cases:
        _fill_missing(
            conn, str(case_id), str(subcategory), str(expected), target_pin, correlation_id, stub,
            kill_after_calls=kill_after_calls,
        )
    _maybe_kill(kill_at, "before_cache")
    for case_id, _category, _subcategory, _invariant, _expected, _exploit_id in cases:
        _cache_lifecycle(conn, str(case_id), target_pin, previous_pin)
    _maybe_kill(kill_at, "before_fix_validation")
    for case_id, _category, _subcategory, _invariant, _expected, exploit_id in cases:
        _update_fix_validation(
            conn, str(exploit_id), str(case_id), target_pin, previous_pin, reports_dir=reports_dir
        )
    detections = [
        item
        for case_id, category, _subcategory, _invariant, _expected, _exploit_id in cases
        if (item := _detect(conn, str(case_id), str(category), target_pin, previous_pin, correlation_id)) is not None
    ]
    _maybe_kill(kill_at, "before_done")
    with conn:
        handoff = conn.execute(
            "UPDATE version_handoffs SET status = 'done' WHERE id = ? AND status = 'claimed' AND claimed_by = ?",
            (handoff_id, correlation_id),
        )
        job = conn.execute(
            "UPDATE regression_jobs SET status = 'done' WHERE handoff_id = ? AND status = 'claimed' AND claimed_by = ?",
            (handoff_id, correlation_id),
        )
        if handoff.rowcount != 1 or job.rowcount != 1:
            raise sqlite3.IntegrityError("completion missed the owner")
    if detections:
        first = detections[0]
        halt(conn, correlation_id, "regression_detected", str(first["detail"]), retryable=False, role="harness")
        return SuiteResult(correlation_id, target_pin, "regression_detected", cases=len(cases), detections=detections)
    return SuiteResult(correlation_id, target_pin, "done", cases=len(cases))


def predecessor_valid(conn: sqlite3.Connection, handoff_id: int) -> bool:
    """True when previous_pin is the immediately preceding recorded pin and that pin's suite is complete.

    Order is version_baselines then version_handoffs by id, never lexicographic hash order. A handoff whose
    recorded previous pin is a later or greater hash is invalid. A previous handoff that is not done is invalid.
    """
    row = conn.execute("SELECT previous_pin FROM version_handoffs WHERE id = ?", (handoff_id,)).fetchone()
    if row is None:
        return False
    recorded = str(row[0])
    chain = [
        str(item[0])
        for item in conn.execute("SELECT target_pin FROM version_baselines ORDER BY id")
    ]
    chain.extend(str(item[0]) for item in conn.execute("SELECT target_pin FROM version_handoffs ORDER BY id"))
    target = conn.execute("SELECT target_pin FROM version_handoffs WHERE id = ?", (handoff_id,)).fetchone()
    if target is None or str(target[0]) not in chain:
        return False
    index = chain.index(str(target[0]))
    if index == 0 or chain[index - 1] != recorded:
        return False
    if conn.execute("SELECT 1 FROM version_baselines WHERE target_pin = ?", (recorded,)).fetchone() is not None:
        return True
    previous = conn.execute("SELECT status FROM version_handoffs WHERE target_pin = ?", (recorded,)).fetchone()
    return previous is not None and str(previous[0]) == "done"


def _maybe_kill(kill_at: str | None, point: str) -> None:
    if kill_at == point:
        raise SuiteKill(point)


def _fill_missing(
    conn: sqlite3.Connection,
    case_id: str,
    subcategory: str,
    expected: str,
    target_pin: str,
    correlation_id: str,
    stub: StubTarget,
    kill_after_calls: int | None = None,
) -> None:
    """Execute only repeats that have no committed row. A committed row is not sent again."""
    present = {item["repeat_index"] for item in outcomes(conn, case_id, target_pin)}
    sequence_hash = conn.execute(
        "SELECT sequence_hash FROM exploits WHERE id = (SELECT exploit_id FROM regression_cases WHERE id = ?)",
        (case_id,),
    ).fetchone()
    digest = "" if sequence_hash is None else str(sequence_hash[0])
    for index in range(1, REPEATS + 1):
        if index in present:
            continue
        observed = stub.respond(digest)
        result = grade(subcategory, observed)
        outcome = result.outcome
        # Wording that matches the expected text is not a fix when the invariant did not pass.
        if outcome != "pass" and expected and expected in observed.body:
            outcome = "wording_only"
        evidence = evidence_of(result, observed)
        if outcome == "wording_only":
            evidence["detail"] = "wording_only"
        with conn:
            insert_regression_run(
                conn,
                grant=issue_grant("harness"),
                case_id=case_id,
                system_version=target_pin,
                correlation_id=correlation_id,
                repeat_index=index,
                outcome=outcome,
                invariant_id=result.invariant_id,
                http_status=observed.http_status,
                evidence=evidence,
                recorded_at=now_iso(),
            )
        if kill_after_calls is not None and len(stub.calls) >= kill_after_calls:
            raise SuiteKill("after_repeat_1")


def _cache_lifecycle(conn: sqlite3.Connection, case_id: str, target_pin: str, previous_pin: str) -> None:
    """Cache the latest pin only. Does not update regression_runs for any pin."""
    current = outcomes(conn, case_id, target_pin)
    if len(current) < REPEATS:
        return
    outcomes_now = [item["outcome"] for item in current]
    previous = outcomes(conn, case_id, previous_pin)
    previous_fixed = len(previous) == REPEATS and all(item["outcome"] == "pass" for item in previous)
    if any(item == "fail" for item in outcomes_now) and previous_fixed:
        lifecycle = "regressed"
    elif all(item == "pass" for item in outcomes_now):
        lifecycle = "fixed"
    else:
        lifecycle = "open"
    with conn:
        conn.execute("UPDATE regression_cases SET lifecycle = ? WHERE id = ?", (lifecycle, case_id))


def _detect(
    conn: sqlite3.Connection,
    case_id: str,
    category: str,
    target_pin: str,
    previous_pin: str,
    correlation_id: str,
) -> ErrorEnvelope | None:
    """Emit at most one envelope per pin and case. A stored detection is returned unchanged."""
    stored = conn.execute(
        "SELECT detail, kind FROM regression_detections WHERE target_pin = ? AND case_id = ?",
        (target_pin, case_id),
    ).fetchone()
    if stored is not None:
        return _envelope(correlation_id, str(stored[0]))
    current = outcomes(conn, case_id, target_pin)
    if len(current) < REPEATS or not any(item["outcome"] == "fail" for item in current):
        return None
    previous = outcomes(conn, case_id, previous_pin)
    if not (len(previous) == REPEATS and all(item["outcome"] == "pass" for item in previous)):
        return None
    kind = "reappearance"
    # Cross-category only when a different category's previously fixed case also failed on this pin.
    cross = conn.execute(
        """
        SELECT c.id FROM regression_cases c
        WHERE c.id != ? AND c.category != ?
          AND EXISTS (
            SELECT 1 FROM regression_runs r
            WHERE r.case_id = c.id AND r.system_version = ? AND r.outcome = 'fail'
          )
          AND (
            SELECT COUNT(*) FROM regression_runs p
            WHERE p.case_id = c.id AND p.system_version = ? AND p.outcome = 'pass'
          ) = 3
        """,
        (case_id, category, target_pin, previous_pin),
    ).fetchone()
    if cross is not None:
        kind = "cross_category"
    detail = f"{kind} case {case_id} previous {previous_pin} pin {target_pin}"
    if cross is not None:
        detail = f"{detail} other {cross[0]}"
    with conn:
        conn.execute(
            """
            INSERT INTO regression_detections (target_pin, case_id, correlation_id, kind, detail, recorded_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (target_pin, case_id, correlation_id, kind, detail[:500], now_iso()),
        )
    return _envelope(correlation_id, detail[:500])


def _update_fix_validation(
    conn: sqlite3.Connection,
    exploit_id: str,
    case_id: str,
    target_pin: str,
    previous_pin: str,
    *,
    reports_dir: Path | None = None,
) -> None:
    """Rewrite fix-validation from committed runs. Publication status is not touched."""
    report = conn.execute("SELECT id, status, body FROM reports WHERE exploit_id = ?", (exploit_id,)).fetchone()
    if report is None:
        return
    current = outcomes(conn, case_id, target_pin)
    previous = outcomes(conn, case_id, previous_pin)
    if len(current) < REPEATS:
        label, pin, run_ids = "not_run", None, ""
    elif all(item["outcome"] == "pass" for item in current):
        label, pin = "fixed", target_pin
        run_ids = ",".join(str(item["id"]) for item in current)
    elif any(item["outcome"] == "fail" for item in current) and _previous_fixed(conn, case_id, previous_pin):
        label = "regressed"
        pin = f"{previous_pin},{target_pin}"
        run_ids = ",".join(str(item["id"]) for item in previous + current)
    else:
        label, pin = "not_fixed", target_pin
        run_ids = ",".join(str(item["id"]) for item in current)
    body = _replace_fix_line(str(report[2]), label, pin, run_ids)
    with conn:
        conn.execute(
            """
            UPDATE reports SET fix_validation = ?, fix_validation_pin = ?, evidence_run_ids = ?, body = ?, updated_at = ?
            WHERE exploit_id = ? AND status = ?
            """,
            (label, pin, run_ids, body, now_iso(), exploit_id, report[1]),
        )
    if reports_dir is not None:
        write_report_markdown(reports_dir, str(report[0]), body)


def _previous_fixed(conn: sqlite3.Connection, case_id: str, previous_pin: str) -> bool:
    previous = outcomes(conn, case_id, previous_pin)
    return len(previous) == REPEATS and all(item["outcome"] == "pass" for item in previous)


def _replace_fix_line(body: str, label: str, pin: str | None, run_ids: str) -> str:
    line = fix_validation_line(label, pin, run_ids)
    lines = body.splitlines()
    replaced = [line if item.startswith("Fix validation:") else item for item in lines]
    if not any(item.startswith("Fix validation:") for item in lines):
        replaced.append(line)
    return "\n".join(replaced)


def _envelope(correlation_id: str, detail: str) -> ErrorEnvelope:
    body: ErrorEnvelope = {
        "error_code": "regression_detected",
        "correlation_id": correlation_id,
        "schema_version": "v1",
        "retryable": False,
        "detail": detail[:500],
    }
    validate("regression_detected", body)
    return body


def _stored(conn: sqlite3.Connection, target_pin: str, correlation_id: str) -> list[ErrorEnvelope]:
    rows = conn.execute(
        "SELECT detail FROM regression_detections WHERE target_pin = ? AND correlation_id = ? ORDER BY id",
        (target_pin, correlation_id),
    ).fetchall()
    return [_envelope(correlation_id, str(row[0])) for row in rows]


def job_depth(conn: sqlite3.Connection) -> int:
    """Pending plus claimed. Done jobs are not backlog. One worker, so this is not a parallel queue."""
    row = conn.execute("SELECT COUNT(*) FROM regression_jobs WHERE status IN ('pending', 'claimed')").fetchone()
    return int(row[0]) if row else 0


def suite_result_json(result: SuiteResult) -> str:
    """A stable print form for the dry-run script. No transcript."""
    return json.dumps(
        {
            "correlation_id": result.correlation_id,
            "target_pin": result.target_pin,
            "status": result.status,
            "cases": result.cases,
            "detections": [item.get("detail", "") for item in result.detections],
        },
        sort_keys=True,
    )
