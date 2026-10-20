"""P6 dispatch journal: crash windows, unknown outcomes and exactly-once reconciliation. Scripted, no network."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from datetime import datetime, timezone

import pytest

from agentforge.contracts.validate import ContractError
from agentforge.orchestrator.journal import (
    Answered,
    Journal,
    KillPoint,
    Outcome,
    Refused,
    UnknownOutcome,
    dispatch,
    parse_retry_after,
)
from agentforge.safety.ledger import LedgerError
from tests.fixtures import ScriptedTransport, fresh_process, p6_campaign, p6_env

CID = "corr-p6"
CALL = "executor-corr-p6-1-0"
RESERVE = 0.05


def _kill_at(name: str) -> Callable[[str], None]:
    def hook(point: str) -> None:
        if point == name:
            raise KillPoint(name)

    return hook


def _spend(conn: sqlite3.Connection) -> list[tuple[str, float, float]]:
    rows = conn.execute("SELECT state, reserved_usd, incurred_usd FROM agent_spend ORDER BY call_id").fetchall()
    return [(str(r[0]), float(r[1]), float(r[2])) for r in rows]


def _send(transport: ScriptedTransport, cost: float = RESERVE) -> Callable[[], Outcome]:
    def send() -> Outcome:
        transport("POST", "https://target.example/chat")
        return Outcome(output="reply", incurred_usd=cost, http_status=200)

    return send


def _run(journal: Journal, transport: ScriptedTransport, attempt: int = 0, send: Callable[[], Outcome] | None = None) -> Outcome:
    return dispatch(
        journal, CID, 1, attempt, role="executor", kind="target", intent="turn-1",
        reserve_usd=RESERVE, send=send or _send(transport),
    )


def test_happy_path_settles_once() -> None:
    conn, _ledger, journal = p6_env()
    p6_campaign(conn)
    transport = ScriptedTransport()
    _run(journal, transport)
    row = journal.latest(CID, 1)
    assert row is not None and (row.state, row.settlement) == ("completed", "settled")
    assert row.call_id == CALL and row.output_hash is not None
    assert _spend(conn) == [("incurred", RESERVE, RESERVE)]
    assert len(transport.calls) == 1


def test_kill_before_insert_leaves_nothing() -> None:
    conn, _ledger, journal = p6_env(hook=_kill_at("before_insert"))
    p6_campaign(conn)
    transport = ScriptedTransport()
    with pytest.raises(KillPoint):
        _run(journal, transport)
    _l, journal2 = fresh_process(conn)
    assert journal2.resume_check(CID) == [] and journal2.rows(CID) == []
    assert _spend(conn) == [] and transport.calls == []
    _run(journal2, transport)
    assert _spend(conn) == [("incurred", RESERVE, RESERVE)]


def test_kill_after_intended_insert_reserves_once_on_adopt() -> None:
    conn, _ledger, journal = p6_env(hook=_kill_at("after_intended_insert"))
    p6_campaign(conn)
    with pytest.raises(KillPoint):
        _run(journal, ScriptedTransport())
    assert _spend(conn) == []
    _l, journal2 = fresh_process(conn)
    intended = journal2.resume_check(CID)
    assert [e.state for e in intended] == ["intended"]
    assert journal2.adopt(intended[0].call_id) is not None
    assert _spend(conn) == [("reserved", RESERVE, 0.0)]
    journal2.mark_sent(CALL)
    journal2.complete(CALL, output="reply", incurred_usd=RESERVE)
    assert _spend(conn) == [("incurred", RESERVE, RESERVE)]


def test_kill_after_reserve_adopts_the_open_reservation() -> None:
    conn, _ledger, journal = p6_env(hook=_kill_at("after_reserve"))
    p6_campaign(conn)
    with pytest.raises(KillPoint):
        _run(journal, ScriptedTransport())
    assert _spend(conn) == [("reserved", RESERVE, 0.0)]
    _l, journal2 = fresh_process(conn)
    intended = journal2.resume_check(CID)
    assert journal2.adopt(intended[0].call_id) is not None
    assert _spend(conn) == [("reserved", RESERVE, 0.0)]  # not reserved a second time
    journal2.mark_sent(CALL)
    journal2.complete(CALL, output="reply", incurred_usd=RESERVE)
    assert _spend(conn) == [("incurred", RESERVE, RESERVE)]


@pytest.mark.parametrize("point", ["after_sent", "after_transport"])
def test_kill_after_sent_halts_as_unknown_and_never_replays(point: str) -> None:
    conn, _ledger, journal = p6_env(hook=_kill_at(point))
    p6_campaign(conn)
    transport = ScriptedTransport()
    with pytest.raises(KillPoint):
        _run(journal, transport)
    before = len(transport.calls)
    ledger2, journal2 = fresh_process(conn)
    with pytest.raises(UnknownOutcome) as caught:
        journal2.resume_check(CID)
    assert caught.value.call_id == CALL
    assert len(transport.calls) == before
    assert _spend(conn) == [("reserved", RESERVE, 0.0)]
    assert ledger2.totals().reserved_usd == RESERVE
    with pytest.raises(UnknownOutcome):
        journal2.resume_check(CID)
    assert len(transport.calls) == before


def test_accept_unknown_settles_through_the_orphan_path_once() -> None:
    conn, _ledger, journal = p6_env(hook=_kill_at("after_sent"))
    p6_campaign(conn)
    with pytest.raises(KillPoint):
        _run(journal, ScriptedTransport())
    ledger2, journal2 = fresh_process(conn)
    accepted = journal2.accept_unknown(CALL)
    assert accepted.settlement == "settled" and accepted.state == "abandoned"
    assert _spend(conn) == [("incurred", RESERVE, RESERVE)]
    assert ledger2.totals().incurred_usd == RESERVE
    with pytest.raises(ContractError):
        journal2.accept_unknown(CALL)
    assert _spend(conn) == [("incurred", RESERVE, RESERVE)]
    # The call_id is never reserved a second time.
    with pytest.raises(ContractError):
        journal2.intend(CID, 1, 0, role="executor", kind="target", intent="turn-1", reserve_usd=RESERVE)
    assert journal2.resume_check(CID) == []


def test_accept_unknown_with_evidence_cannot_exceed_the_reservation() -> None:
    conn, _ledger, journal = p6_env(hook=_kill_at("after_sent"))
    p6_campaign(conn)
    with pytest.raises(KillPoint):
        _run(journal, ScriptedTransport())
    _l, journal2 = fresh_process(conn)
    with pytest.raises(ContractError):
        journal2.accept_unknown(CALL, evidence_usd=RESERVE + 0.01)
    journal2.accept_unknown(CALL, evidence_usd=0.01)
    assert _spend(conn) == [("incurred", RESERVE, 0.01)]


def test_kill_after_completed_reconciles_exactly_once() -> None:
    conn, _ledger, journal = p6_env(hook=_kill_at("after_completed"))
    p6_campaign(conn)
    transport = ScriptedTransport()
    with pytest.raises(KillPoint):
        _run(journal, transport)
    row = journal.latest(CID, 1)
    assert row is not None and (row.state, row.settlement) == ("completed", "pending")
    assert _spend(conn) == [("reserved", RESERVE, 0.0)]
    ledger2, journal2 = fresh_process(conn)
    assert journal2.resume_check(CID) == []
    assert _spend(conn) == [("incurred", RESERVE, RESERVE)]
    settled = journal2.latest(CID, 1)
    assert settled is not None and settled.settlement == "settled"
    for _ in range(2):
        assert journal2.reconcile(CID) == []
        journal2.resume_check(CID)
    assert _spend(conn) == [("incurred", RESERVE, RESERVE)]
    assert ledger2.totals().incurred_usd == RESERVE
    assert len(transport.calls) == 1


def test_kill_between_incur_and_settled_only_updates_the_journal() -> None:
    conn, _ledger, journal = p6_env(hook=_kill_at("after_incur"))
    p6_campaign(conn)
    with pytest.raises(KillPoint):
        _run(journal, ScriptedTransport())
    row = journal.latest(CID, 1)
    assert row is not None and row.settlement == "pending"
    assert _spend(conn) == [("incurred", RESERVE, RESERVE)]
    ledger2, journal2 = fresh_process(conn)
    assert journal2.reconcile(CID) == [row.call_id]
    assert _spend(conn) == [("incurred", RESERVE, RESERVE)]
    assert ledger2.totals().incurred_usd == RESERVE


def test_reconcile_refuses_a_released_ledger_row_under_a_completed_entry() -> None:
    conn, _ledger, journal = p6_env(hook=_kill_at("after_completed"))
    p6_campaign(conn)
    with pytest.raises(KillPoint):
        _run(journal, ScriptedTransport())
    conn.execute("UPDATE agent_spend SET state = 'released', reserved_usd = 0 WHERE call_id = ?", (CALL,))
    _l, journal2 = fresh_process(conn)
    with pytest.raises(ContractError, match="released"):
        journal2.reconcile(CID)


def test_reconcile_refuses_a_journal_amount_above_the_reservation() -> None:
    conn, _ledger, journal = p6_env(hook=_kill_at("after_completed"))
    p6_campaign(conn)
    with pytest.raises(KillPoint):
        _run(journal, ScriptedTransport())
    conn.execute("UPDATE dispatch_journal SET incurred_usd = 1.0 WHERE call_id = ?", (CALL,))
    _l, journal2 = fresh_process(conn)
    with pytest.raises(ContractError, match="exceeds"):
        journal2.reconcile(CID)
    assert _spend(conn) == [("reserved", RESERVE, 0.0)]
    with pytest.raises(ContractError):
        journal2.complete(CALL, output="x", incurred_usd=1.0)


def test_reconcile_marks_an_already_incurred_row_without_a_second_charge() -> None:
    conn, _ledger, journal = p6_env(hook=_kill_at("after_incur"))
    p6_campaign(conn)
    with pytest.raises(KillPoint):
        _run(journal, ScriptedTransport())
    _l, journal2 = fresh_process(conn)
    journal2.reconcile_one(CALL)
    assert _spend(conn) == [("incurred", RESERVE, RESERVE)]
    assert journal2.reconcile_one(CALL) == "noop"


def test_zero_cost_completed_call_leaves_no_dangling_reservation() -> None:
    conn, ledger, journal = p6_env()
    p6_campaign(conn)
    dispatch(
        journal, CID, 2, 0, role="executor", kind="target", intent="identity", reserve_usd=0.0,
        send=lambda: Outcome(output="ok", incurred_usd=0.0, http_status=200),
    )
    assert _spend(conn) == [("incurred", 0.0, 0.0)]
    assert ledger.totals().reserved_usd == 0.0


def test_reconcile_never_touches_intended_sent_or_unknown_rows() -> None:
    conn, _ledger, journal = p6_env(hook=_kill_at("after_sent"))
    p6_campaign(conn)
    with pytest.raises(KillPoint):
        _run(journal, ScriptedTransport())
    _l, journal2 = fresh_process(conn)
    assert journal2.reconcile(CID) == []
    row = journal2.get(CALL)
    assert row is not None and row.state == "sent" and row.settlement == "none"
    assert _spend(conn) == [("reserved", RESERVE, 0.0)]


def test_refusal_and_answered_status_release_but_transport_error_holds() -> None:
    conn, _ledger, journal = p6_env()
    p6_campaign(conn)

    def refuse() -> Outcome:
        raise Refused("allowlist", "off list")

    with pytest.raises(Refused):
        dispatch(journal, CID, 1, 0, role="executor", kind="target", intent="a", reserve_usd=RESERVE, send=refuse)

    def throttled() -> Outcome:
        raise Answered(429, 2.0, "slow down")

    with pytest.raises(Answered):
        dispatch(journal, CID, 2, 0, role="executor", kind="target", intent="b", reserve_usd=RESERVE, send=throttled)
    row = journal.latest(CID, 2)
    assert row is not None and (row.http_status, row.retry_after_s, row.state) == (429, 2.0, "abandoned")
    assert [s for s, _r, _i in _spend(conn)] == ["released", "released"]

    def reset() -> Outcome:
        raise ConnectionResetError("reset after write")

    with pytest.raises(UnknownOutcome):
        dispatch(journal, CID, 3, 0, role="executor", kind="target", intent="c", reserve_usd=RESERVE, send=reset)
    assert sorted(s for s, _r, _i in _spend(conn)) == ["released", "released", "reserved"]
    with pytest.raises(UnknownOutcome):
        journal.resume_check(CID)


def test_a_refused_reserve_abandons_the_row_and_sends_nothing() -> None:
    conn, _ledger, journal = p6_env(max_attacks=0)
    p6_campaign(conn)
    transport = ScriptedTransport()
    with pytest.raises(Exception):
        _run(journal, transport)
    assert transport.calls == [] and _spend(conn) == []
    row = journal.get(CALL)
    assert row is not None and row.state == "abandoned"


def test_next_attempt_uses_a_new_call_id() -> None:
    conn, _ledger, journal = p6_env()
    p6_campaign(conn)

    def throttled() -> Outcome:
        raise Answered(503, None, "busy")

    with pytest.raises(Answered):
        _run(journal, ScriptedTransport(), send=throttled)
    assert journal.next_attempt(CID, 1) == 1
    _run(journal, ScriptedTransport(), attempt=1)
    assert [e.call_id for e in journal.rows(CID)] == [CALL, "executor-corr-p6-1-1"]
    assert _spend(conn) == [("released", 0.0, 0.0), ("incurred", RESERVE, RESERVE)]


def test_retry_after_parsing() -> None:
    now = datetime(2026, 10, 19, 12, 0, 0, tzinfo=timezone.utc)
    assert parse_retry_after("2", now=now) == 2.0
    assert parse_retry_after("Mon, 19 Oct 2026 12:00:30 GMT", now=now) == 30.0
    assert parse_retry_after("soon") is None
    assert parse_retry_after("-3") is None
    assert parse_retry_after(None) is None
    assert parse_retry_after("") is None


def test_journal_row_holds_hashes_not_bodies() -> None:
    conn, _ledger, journal = p6_env()
    p6_campaign(conn)
    secret = "COOKIE-SECRET-VALUE-123"
    dispatch(
        journal, CID, 1, 0, role="executor", kind="target", intent="body " + secret, reserve_usd=0.0,
        send=lambda: Outcome(output="reply " + secret, incurred_usd=0.0),
    )
    dump = " ".join(str(v) for r in conn.execute("SELECT * FROM dispatch_journal") for v in r)
    assert secret not in dump
    with pytest.raises(LedgerError):
        journal._ledger.combined(CALL)
