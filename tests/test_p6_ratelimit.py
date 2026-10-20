"""P6 bounded 429/503 policy and non-retryable classification. Scripted, injected clock and sleep, no network."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from datetime import datetime, timezone

import pytest

from agentforge.orchestrator.journal import Journal, NotSent, Outcome, UnknownOutcome, parse_retry_after
from agentforge.orchestrator.policy import RetryPolicy
from agentforge.orchestrator.retry import StepHalt, backoff_delay, rate_detail, run_step
from agentforge.safety.chokepoint import RefusedByChokepoint, Response
from agentforge.safety.phi import PhiRefused
from agentforge.safety.rate import RateCap, RateCapExceeded
from tests.fixtures import ScriptedTransport, p6_campaign, p6_env

CID = "corr-p6"
RESERVE = 0.05
POLICY = RetryPolicy(max_attempts_per_step=3, max_attempts_per_campaign=6, base_delay_s=1.0, max_delay_s=30.0)
NOW = datetime(2026, 10, 19, 12, 0, 0, tzinfo=timezone.utc)


class Sleeps:
    def __init__(self) -> None:
        self.calls: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


def _sender(
    transport: ScriptedTransport, rate_cap: RateCap | None = None, identity: list[int] | None = None
) -> Callable[[int], Callable[[], Outcome]]:
    """Each attempt re-checks identity, reserves a RateCap slot and sends through the scripted transport."""

    def make(_attempt: int) -> Callable[[], Outcome]:
        def send() -> Outcome:
            if identity is not None:
                identity.append(1)
            if rate_cap is not None:
                rate_cap.reserve()
            reply = transport("POST", "https://target.example/chat")
            assert isinstance(reply, Response)
            after = parse_retry_after((reply.headers or {}).get("Retry-After"), now=NOW)
            cost = RESERVE if reply.status < 400 else 0.0
            return Outcome(output=reply.body.decode(), incurred_usd=cost, http_status=reply.status, retry_after_s=after)

        return send

    return make


def _step(
    journal: Journal,
    conn: sqlite3.Connection,
    sleeps: Sleeps,
    make_send: Callable[[int], Callable[[], Outcome]],
    step: int = 1,
    policy: RetryPolicy = POLICY,
) -> Outcome:
    return run_step(
        journal, conn, policy, CID, step, role="executor", kind="target", intent="turn", reserve_usd=RESERVE,
        make_send=make_send, sleep=sleeps, clock=lambda: NOW,
    )


def _spend(conn: sqlite3.Connection) -> list[tuple[str, float, float]]:
    rows = conn.execute("SELECT state, reserved_usd, incurred_usd FROM agent_spend ORDER BY call_id").fetchall()
    return [(str(r[0]), float(r[1]), float(r[2])) for r in rows]


def test_429_with_retry_after_then_ok_sleeps_and_keeps_status() -> None:
    conn, _ledger, journal = p6_env()
    p6_campaign(conn)
    transport = ScriptedTransport([Response(429, b"", headers={"Retry-After": "2"}), Response(200, b"ok")])
    sleeps = Sleeps()
    outcome = _step(journal, conn, sleeps, _sender(transport))
    assert outcome.http_status == 200 and len(transport.calls) == 2
    assert sleeps.calls and sleeps.calls[0] >= 2
    first, second = journal.rows(CID)
    assert (first.http_status, first.retry_after_s, first.state, first.attempt) == (429, 2.0, "abandoned", 0)
    assert (second.state, second.attempt) == ("completed", 1)
    assert first.call_id != second.call_id
    assert sorted(_spend(conn)) == sorted([("released", 0.0, 0.0), ("incurred", RESERVE, RESERVE)])


def test_retry_after_forms_parse() -> None:
    assert parse_retry_after("2", now=NOW) == 2.0
    assert parse_retry_after("Mon, 19 Oct 2026 12:00:10 GMT", now=NOW) == 10.0
    assert parse_retry_after("soon", now=NOW) is None
    assert parse_retry_after(None, now=NOW) is None
    assert parse_retry_after("", now=NOW) is None


@pytest.mark.parametrize(
    ("headers", "expected", "slept"),
    [
        ({"Retry-After": "Mon, 19 Oct 2026 12:00:05 GMT"}, 5.0, 5.0),
        ({"Retry-After": "garbage"}, None, 1.0),
        (None, None, 1.0),
    ],
)
def test_503_retry_after_variants(headers: dict[str, str] | None, expected: float | None, slept: float) -> None:
    conn, _ledger, journal = p6_env()
    p6_campaign(conn)
    transport = ScriptedTransport([Response(503, b"", headers=headers), Response(200, b"ok")])
    sleeps = Sleeps()
    _step(journal, conn, sleeps, _sender(transport))
    assert journal.rows(CID)[0].http_status == 503
    assert journal.rows(CID)[0].retry_after_s == expected
    assert sleeps.calls[0] == slept


def test_backoff_is_exponential_capped_and_respects_retry_after() -> None:
    assert [backoff_delay(n, None, POLICY) for n in range(7)] == [1.0, 2.0, 4.0, 8.0, 16.0, 30.0, 30.0]
    assert backoff_delay(0, 7.0, POLICY) == 7.0
    assert backoff_delay(0, 99.0, POLICY) == 30.0


def test_retry_after_above_the_cap_halts_without_sleeping() -> None:
    conn, _ledger, journal = p6_env()
    p6_campaign(conn)
    transport = ScriptedTransport([Response(429, b"", headers={"Retry-After": "120"})])
    sleeps = Sleeps()
    with pytest.raises(StepHalt) as caught:
        _step(journal, conn, sleeps, _sender(transport))
    halt = caught.value.halt
    assert (halt.code, halt.retryable) == ("target_unreachable", True)
    assert halt.next_attempt_at == "2026-10-19T12:02:00Z"
    assert halt.detail == rate_detail(429, 120.0) == "rate_limited status=429 retry_after_s=120"
    assert sleeps.calls == [] and len(transport.calls) == 1


def test_persistent_429_stops_at_the_step_bound() -> None:
    conn, _ledger, journal = p6_env()
    p6_campaign(conn)
    transport = ScriptedTransport([Response(429, b"")])
    sleeps = Sleeps()
    with pytest.raises(StepHalt) as caught:
        _step(journal, conn, sleeps, _sender(transport))
    assert (caught.value.halt.code, caught.value.halt.retryable) == ("target_unreachable", True)
    assert "status=429" in caught.value.halt.detail
    assert len(transport.calls) == POLICY.max_attempts_per_step == 3
    assert len(sleeps.calls) == 2  # no sleep after the last attempt
    assert _spend(conn) == [("released", 0.0, 0.0)] * 3


def test_persistent_429_stops_at_the_campaign_bound_across_steps() -> None:
    conn, _ledger, journal = p6_env()
    p6_campaign(conn)
    transport = ScriptedTransport([Response(429, b"")])
    sleeps = Sleeps()
    for step in (1, 2):
        with pytest.raises(StepHalt):
            _step(journal, conn, sleeps, _sender(transport), step)
    assert len(transport.calls) == POLICY.max_attempts_per_campaign == 6
    with pytest.raises(StepHalt) as caught:
        _step(journal, conn, sleeps, _sender(transport), 3)
    assert caught.value.halt.retryable is True and "campaign attempt bound" in caught.value.halt.detail
    assert len(transport.calls) == 6


@pytest.mark.parametrize("status", [400, 401, 403, 404, 409, 500, 502, 504])
def test_non_retryable_statuses_halt_at_once(status: int) -> None:
    conn, _ledger, journal = p6_env()
    p6_campaign(conn)
    transport = ScriptedTransport([Response(status, b"")])
    sleeps = Sleeps()
    with pytest.raises(StepHalt) as caught:
        _step(journal, conn, sleeps, _sender(transport))
    assert (caught.value.halt.code, caught.value.halt.retryable) == ("target_unreachable", False)
    assert len(transport.calls) == 1 and sleeps.calls == []
    assert journal.rows(CID)[0].http_status == status
    assert _spend(conn) == [("released", 0.0, 0.0)]


@pytest.mark.parametrize(
    ("exc", "code"),
    [
        (RefusedByChokepoint("allowlist", "not allowed"), "target_unreachable"),
        (RefusedByChokepoint("identity", "mismatch"), "target_unreachable"),
        (PhiRefused(("mrn",)), "target_unreachable"),
        (RefusedByChokepoint("budget", "no headroom"), "budget_exceeded"),
        (RateCapExceeded("cap"), "budget_exceeded"),
    ],
)
def test_local_refusals_halt_at_once_without_retry(exc: Exception, code: str) -> None:
    conn, _ledger, journal = p6_env()
    p6_campaign(conn)
    calls: list[int] = []

    def make(_attempt: int) -> Callable[[], Outcome]:
        def send() -> Outcome:
            calls.append(1)
            raise exc

        return send

    sleeps = Sleeps()
    with pytest.raises(StepHalt) as caught:
        _step(journal, conn, sleeps, make)
    assert (caught.value.halt.code, caught.value.halt.retryable) == (code, False)
    assert len(calls) == 1 and sleeps.calls == []
    assert _spend(conn) == [("released", 0.0, 0.0)]


def test_timeout_after_write_is_unknown_outcome_not_backoff() -> None:
    conn, _ledger, journal = p6_env()
    p6_campaign(conn)
    transport = ScriptedTransport([TimeoutError("read timed out")])
    sleeps = Sleeps()
    with pytest.raises(UnknownOutcome):
        _step(journal, conn, sleeps, _sender(transport))
    assert len(transport.calls) == 1 and sleeps.calls == []
    assert journal.rows(CID)[0].state == "unknown"
    assert _spend(conn) == [("reserved", RESERVE, 0.0)]  # the reservation is held, not released


def test_connection_error_before_write_is_retryable() -> None:
    conn, _ledger, journal = p6_env()
    p6_campaign(conn)
    count = {"n": 0}

    def make(_attempt: int) -> Callable[[], Outcome]:
        def send() -> Outcome:
            count["n"] += 1
            if count["n"] == 1:
                raise NotSent("connection refused before write")
            return Outcome(output="ok", incurred_usd=RESERVE, http_status=200)

        return send

    sleeps = Sleeps()
    outcome = _step(journal, conn, sleeps, make)
    assert outcome.http_status == 200 and count["n"] == 2 and sleeps.calls == [1.0]
    assert [r.state for r in journal.rows(CID)] == ["abandoned", "completed"]


def test_every_retry_reserves_again_checks_identity_and_takes_a_rate_slot() -> None:
    conn, _ledger, journal = p6_env()
    p6_campaign(conn)
    transport = ScriptedTransport([Response(429, b""), Response(429, b""), Response(200, b"ok")])
    cap, identity = RateCap(10), []
    _step(journal, conn, Sleeps(), _sender(transport, cap, identity))
    assert len(identity) == 3 and cap.used == 3
    assert len(journal.rows(CID)) == 3
    assert len({r.call_id for r in journal.rows(CID)}) == 3
    assert len(_spend(conn)) == 3  # one ledger row per attempt


def test_exhausted_rate_cap_ends_the_retries() -> None:
    conn, _ledger, journal = p6_env()
    p6_campaign(conn)
    transport = ScriptedTransport([Response(429, b"")])
    cap = RateCap(2)
    with pytest.raises(StepHalt) as caught:
        _step(journal, conn, Sleeps(), _sender(transport, cap))
    assert (caught.value.halt.code, caught.value.halt.retryable) == ("budget_exceeded", False)
    assert len(transport.calls) == 2


def test_a_refused_reservation_halts_without_sending() -> None:
    conn, ledger, journal = p6_env(max_attacks=1)
    p6_campaign(conn)
    ledger.reserve("held-elsewhere", "target", 0.01)  # takes the only attack slot
    transport = ScriptedTransport([Response(200, b"ok")])
    with pytest.raises(StepHalt) as caught:
        _step(journal, conn, Sleeps(), _sender(transport))
    assert (caught.value.halt.code, caught.value.halt.retryable) == ("budget_exceeded", False)
    assert transport.calls == []
    assert journal.rows(CID)[0].state == "abandoned"
