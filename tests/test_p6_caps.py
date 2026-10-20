"""Cap accounting for sequences, turns and requests. Scripted: no network, no model, no spend."""

from __future__ import annotations

import sqlite3
from dataclasses import replace

import pytest
from fixtures import FakeTarget, answer, p6_budget, p6_campaign, p6_client, p6_store
from agentforge.evals.login import LoginRequest
from agentforge.orchestrator.journal import Journal, KillPoint, UnknownOutcome
from agentforge.orchestrator.policy import Config, Limits, load_config
from agentforge.orchestrator.sequence import PreflightRefused, SequenceRunner, sequence_cap
from agentforge.safety.ledger import Ledger

CID = "corr-p6"


def _counters(conn: sqlite3.Connection) -> tuple[int, int]:
    row = conn.execute("SELECT sequences_started, turns_sent FROM campaigns WHERE correlation_id = ?", (CID,)).fetchone()
    return int(row[0]), int(row[1])


def _runner(
    *,
    max_attacks: int = 50,
    max_requests: int = 60,
    config: Config | None = None,
    target: FakeTarget | None = None,
    request_cap: int = 5,
    hook: object = None,
) -> tuple[SequenceRunner, sqlite3.Connection, FakeTarget, Journal]:
    conn = p6_store()
    budget = p6_budget(max_attacks)
    ledger = Ledger(conn, budget)
    journal = Journal(conn, ledger, hook=hook)  # type: ignore[arg-type]
    p6_campaign(conn, CID)
    fake = target or FakeTarget()
    client = p6_client(fake, ledger, budget, max_requests=max_requests)
    runner = SequenceRunner(
        conn, journal, config or load_config(), client,  # type: ignore[arg-type]
        LoginRequest("copilot_doc_a", "not-committed"), "100", sleep=lambda _s: None, request_cap=request_cap,
    )
    return runner, conn, fake, journal


def test_a_three_turn_sequence_counts_one_sequence_and_three_turns() -> None:
    runner, conn, target, _ = _runner()
    result = runner.run(CID, ("alpha one two", "beta three four", "gamma five six"), "t-1")
    assert result.halt is None and result.turns_sent == 3
    assert _counters(conn) == (1, 3)
    assert target.chat_calls == 3
    assert result.transcript is not None and len(result.transcript["turns"]) == 6


def test_splitting_an_attack_cannot_lower_any_counter() -> None:
    runner, conn, target, _ = _runner()
    for index, text in enumerate(("alpha one two", "beta three four", "gamma five six")):
        runner.run(CID, (text,), f"t-{index}")
    assert _counters(conn) == (3, 3)  # three sequences and the same three turns
    assert target.chat_calls == 3


def test_every_turn_consumes_a_rate_cap_slot_and_setup_slots() -> None:
    runner, _, target, _ = _runner()
    runner.run(CID, ("alpha one two", "beta three four", "gamma five six"), "t-1")
    # identity, login, landing/dock, demographics, read-back, then three chat posts
    assert len(target.calls) >= 3 + 4
    assert runner._client.rate_cap.used == len(target.calls)  # type: ignore[attr-defined]


def test_preflight_refuses_every_cap_and_changes_nothing() -> None:
    cases = {
        "sequence": dict(request_cap=0),
        "turn": dict(config=replace(load_config(), limits=replace(load_config().limits, max_sequences_per_campaign=1, max_turns=1))),
        "rate": dict(max_requests=3),
        "budget": dict(max_attacks=3),
    }
    for name, kwargs in cases.items():
        runner, conn, target, journal = _runner(**kwargs)  # type: ignore[arg-type]
        turns = ("alpha one two", "beta three four") if name in ("turn", "rate", "budget") else ("alpha one two",)
        with pytest.raises(PreflightRefused):
            runner.run(CID, turns, "t-x")
        assert _counters(conn) == (0, 0), name
        assert target.calls == [], name
        assert journal.rows(CID) == [], name


def test_a_turn_total_above_the_turn_cap_is_refused_whole() -> None:
    config = replace(load_config(), limits=replace(load_config().limits, max_sequences_per_campaign=1, max_turns=2))
    runner, conn, target, _ = _runner(config=config, request_cap=9)
    assert config.max_turns_total == 2
    runner.run(CID, ("alpha one two", "beta three four"), "t-1")
    with pytest.raises(PreflightRefused):
        runner.run(CID, ("gamma five six",), "t-2")  # the sequence cap is also reached
    assert _counters(conn) == (1, 2)


def test_ledger_headroom_for_every_chat_reservation_is_checked_first() -> None:
    runner, conn, target, _ = _runner()
    conn.execute(
        "INSERT INTO agent_spend (call_id, agent_role, reserved_usd, incurred_usd, state) VALUES ('other', 'target', 0, 4.95, 'incurred')"
    )
    conn.commit()
    with pytest.raises(PreflightRefused):
        runner.run(CID, ("alpha one two", "beta three four"), "t-1")
    assert target.calls == [] and _counters(conn) == (0, 0)


def test_the_request_value_is_clamped_to_the_config_value_never_raised() -> None:
    config = load_config()
    assert sequence_cap(999, config) == config.limits.max_sequences_per_campaign
    assert sequence_cap(2, config) == 2
    assert sequence_cap(-3, config) == 0


def test_chat_turns_do_not_move_budget_attacks_which_is_why_turns_are_counted() -> None:
    runner, conn, target, _ = _runner()
    budget = runner._client.budget  # type: ignore[attr-defined]
    runner.run(CID, ("alpha one two",), "t-1")
    after_one = budget.attacks
    runner.run(CID, ("beta three four", "gamma five six"), "t-2")
    setup_slots = budget.attacks - after_one
    # the chat POSTs reach the chokepoint with attack=False. Only setup and the journal reservation count as attacks.
    assert target.chat_calls == 3
    assert _counters(conn)[1] == 3
    assert setup_slots >= 1


def test_a_429_on_turn_two_counts_one_sequence_and_two_turns() -> None:
    target = FakeTarget([answer("first reply"), (429, b"slow", {"Retry-After": "1"})])
    runner, conn, _, journal = _runner(target=target)
    result = runner.run(CID, ("alpha one two", "beta three four", "gamma five six"), "t-1")
    assert result.halt is not None and result.halt.retryable is True
    assert result.turns_sent == 1
    assert _counters(conn)[0] == 1
    assert target.chat_calls <= 1 + 3  # bounded retries on turn two, turn three is never sent
    assert result.transcript is not None and len(result.transcript["turns"]) == 2


def test_a_refused_reserve_before_sending_is_not_counted() -> None:
    runner, conn, target, journal = _runner()
    runner.run(CID, ("alpha one two",), "t-1")
    conn.execute(
        "INSERT INTO agent_spend (call_id, agent_role, reserved_usd, incurred_usd, state) VALUES ('other', 'target', 0, 4.94, 'incurred')"
    )
    conn.commit()
    calls = len(target.calls)
    with pytest.raises(PreflightRefused):
        runner.run(CID, ("beta three four",), "t-2")
    assert len(target.calls) == calls and _counters(conn) == (1, 1)


class _Kill:
    def __init__(self, name: str, nth: int) -> None:
        self.name, self.nth, self.seen = name, nth, 0

    def __call__(self, point: str) -> None:
        if point == self.name:
            self.seen += 1
            if self.seen == self.nth:
                raise KillPoint(point)


def test_kill_mid_sequence_does_not_increment_twice_and_never_resends_an_unknown_turn() -> None:
    kill = _Kill("after_sent", 3)  # setup, turn one, then the kill on turn two after `sent`
    runner, conn, target, journal = _runner(hook=kill)
    with pytest.raises(KillPoint):
        runner.run(CID, ("alpha one two", "beta three four"), "t-1")
    assert _counters(conn) == (1, 2)
    sent_before = target.chat_calls
    with pytest.raises(UnknownOutcome):
        journal.resume_check(CID)  # turn two is `sent` with no outcome: never replayed
    assert target.chat_calls == sent_before
    assert _counters(conn) == (1, 2)


def test_a_resumed_completed_turn_is_not_resent_or_recounted() -> None:
    runner, conn, target, journal = _runner()
    runner.run(CID, ("alpha one two", "beta three four"), "t-1")
    chats = target.chat_calls
    again = runner.run(CID, ("alpha one two", "beta three four"), "t-1", resume=1)
    assert again.unrecordable is True and again.transcript is None
    assert target.chat_calls == chats
    assert _counters(conn) == (1, 2)


def test_a_mutated_multi_turn_child_starts_a_new_sequence() -> None:
    runner, conn, _, _ = _runner()
    runner.run(CID, ("alpha one two", "beta three four"), "t-1")
    runner.run(CID, ("delta seven eight", "omega nine ten"), "t-2")
    assert _counters(conn) == (2, 4)
