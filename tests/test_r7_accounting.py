"""R7-R8 accounting characterization. Offline, no network, no key, no spend. These tests FIX nothing.

Each test pins what the code does today on one refusal or failure path, so a later change to the safety code shows
up as a deliberate test change. Findings, in the order the plan lists them:

F1  The chokepoint reserves Budget before the spend-limit and rate gates. A refusal at either gate, a transport
    error, and an off-list redirect do not return that reservation. Budget therefore OVERCOUNTS. This is
    conservative: it can only stop work early.
F2  A chat reserve is counted twice in Budget when a client ledger is set: once by the ledger and once by the
    chokepoint estimate. Preflight in sequence.py encodes this as 2 * need. Zero-cost requests count as attacks.
F3  Budget.per_day_usd is a second lifetime cap, not a daily one: nothing resets day_spent. start_run() resets only
    run_spent and the attack count. A new process re-seeds both from the ledger's committed total.
F4  A dispatched chat whose outcome is unknown stays reserved on the client-ledger path. Releasing it at $0 was
    the undercount. The journal path still holds the same failure as `unknown`. The P-U record stays open until
    the operator closes it.
F5  Provider (OpenRouter judge) calls carry no ledger or budget argument. Recording the bill is the caller's job.
    last_cost_usd is None, never zero, when no cost was reported.
F6  A Judge timeout or a transport OSError after the request was handed to the provider holds the reservation.
    A known non-bill, such as a gate refusal or a 429, is still released.
"""

from __future__ import annotations

import inspect
from typing import Any
import sqlite3

import pytest
from fixtures import (
    P6_SECRET,
    TODAY,
    p6_budget,
    p6_caps,
    p6_campaign,
    p6_env,
    p6_store,
)

from agentforge.agents import openrouter as openrouter_module
from agentforge.agents.openrouter import (
    OpenRouterHttpError,
    OpenRouterJudgeModel,
    OpenRouterLabelError,
    ProviderOutcomeUnknown,
)
from agentforge.evals.session import CHAT_PATH, SessionClient, SessionError, TargetStatusError
from agentforge.orchestrator.journal import Outcome, UnknownOutcome, dispatch
from agentforge.safety.allowlist import Allowlist, Entry
from agentforge.safety.budget import Budget, BudgetExceeded, Caps, approval_token
from agentforge.safety.chokepoint import RefusedByChokepoint, Response, request
from agentforge.safety.operator_approval import OperatorApproval
from agentforge.safety.ledger import Ledger, committed_usd, load_shared_budget
from agentforge.safety.rate import RateCap
from agentforge.safety.spend_limits import Attestation

HOST = "target.example"
ORIGIN = f"https://{HOST}"
ALLOW = Allowlist((Entry("https", HOST, 443, "/"),))
ATTEST = [Attestation("target", "target-key", 10.0, "someone", TODAY)]
SSE_OK = b'event: answer\ndata: {"text": "ok"}\n\n'
RESERVE = 0.05


def state(budget: Budget) -> tuple[float, float, int]:
    return (round(budget.run_spent, 6), round(budget.day_spent, 6), budget.attacks)


class Wire:
    """A scripted transport that records each call and can fail with an OSError."""

    def __init__(self, response: Response | None = None, error: OSError | None = None) -> None:
        self.response = response or Response(200, SSE_OK)
        self.error = error
        self.calls: list[tuple[str, str]] = []

    def __call__(self, method: str, url: str, headers: object = None, body: object = None) -> Response:
        self.calls.append((method, url))
        if self.error is not None:
            raise self.error
        return self.response


# ---------------------------------------------------------------------------------------------------------------
# F1, F2: the chokepoint on its own
# ---------------------------------------------------------------------------------------------------------------
def _call(
    wire: Wire,
    budget: Budget,
    *,
    est: float,
    url: str = f"{ORIGIN}/interface/x",
    attestations: list[Attestation] | None = None,
    rate: RateCap | None = None,
    fake: bool = True,
    attack: bool = True,
) -> Response:
    return request(
        "GET",
        url,
        transport=wire,
        allowlist=ALLOW,
        budget=budget,
        attestations=ATTEST if attestations is None else attestations,
        provider="target",
        est_cost_usd=est,
        attack=attack,
        today=TODAY,
        fake_transport=fake,
        rate_cap=rate or RateCap(60),
        approvals=[OperatorApproval("op", TODAY, "public-target", 0.0, "fixture", f"https://{HOST}")],
    )


def test_refusals_before_the_budget_gate_reserve_nothing() -> None:
    cases = [
        {"fake": False, "est": 0.0},  # live flag
        {"url": "https://other.example/x", "est": 0.0},  # allowlist
        {"est": 6.0},  # the budget gate itself refuses
    ]
    for case in cases:
        wire, budget = Wire(), p6_budget()
        with pytest.raises(RefusedByChokepoint):
            _call(wire, budget, **case)  # type: ignore[arg-type]
        assert state(budget) == (0.0, 0.0, 0), case
        assert wire.calls == [], case


def test_spend_limit_refusal_keeps_the_budget_reservation_and_sends_nothing() -> None:
    wire, budget = Wire(), p6_budget()
    with pytest.raises(RefusedByChokepoint) as caught:
        _call(wire, budget, est=RESERVE, attestations=[])
    assert caught.value.gate == "spend_limit"
    assert state(budget) == (RESERVE, RESERVE, 1)  # F1: not returned. Overcounts, never undercounts
    assert wire.calls == []


def test_rate_refusal_keeps_the_attack_count_and_sends_nothing() -> None:
    wire, budget = Wire(), p6_budget()
    with pytest.raises(RefusedByChokepoint) as caught:
        _call(wire, budget, est=0.0, rate=RateCap(0))
    assert caught.value.gate == "rate"
    assert state(budget) == (0.0, 0.0, 1)  # F1
    assert wire.calls == []


def test_transport_error_keeps_the_budget_reservation() -> None:
    wire, budget = Wire(error=ConnectionResetError(54, "reset")), p6_budget()
    with pytest.raises(ConnectionResetError):
        _call(wire, budget, est=RESERVE)
    assert state(budget) == (RESERVE, RESERVE, 1)
    assert len(wire.calls) == 1


def test_off_list_redirect_is_refused_after_the_request_was_sent() -> None:
    wire = Wire(Response(302, b"", location="https://evil.example/x"))
    budget = p6_budget()
    with pytest.raises(RefusedByChokepoint) as caught:
        _call(wire, budget, est=0.0)
    assert caught.value.gate == "allowlist"
    assert state(budget) == (0.0, 0.0, 1)
    assert len(wire.calls) == 1  # the first hop was already sent. Only the second hop is refused


@pytest.mark.parametrize("status", [200, 429, 503])
def test_returned_responses_keep_the_reservation_for_the_caller_to_settle(status: int) -> None:
    wire, budget = Wire(Response(status, b"")), p6_budget()
    assert _call(wire, budget, est=RESERVE).status == status
    assert state(budget) == (RESERVE, RESERVE, 1)


def test_zero_cost_requests_each_count_as_an_attack() -> None:
    wire, budget = Wire(), p6_budget()
    for _ in range(3):
        _call(wire, budget, est=0.0)
    assert state(budget) == (0.0, 0.0, 3)


# ---------------------------------------------------------------------------------------------------------------
# F2, F4: SessionClient.post_chat with a client ledger (the live_campaign.py path)
# ---------------------------------------------------------------------------------------------------------------
def _ledger_client(
    wire: Wire, *, attestations: list[Attestation] | None = None, chat_url: str | None = None
) -> tuple[SessionClient, sqlite3.Connection, Budget]:
    conn, budget = p6_store(), p6_budget()
    client = SessionClient(
        ORIGIN,
        transport=wire,
        allowlist=ALLOW,
        budget=budget,
        attestations=ATTEST if attestations is None else attestations,
        provider="target",
        today=TODAY,
        rate_cap=RateCap(60),
        chat_reserve_usd=RESERVE,
        fake_transport=True,
        ledger=Ledger(conn, budget),
        approvals=[OperatorApproval("op", TODAY, "public-target", 0.0, "fixture", ORIGIN)],
    )
    client.session.csrf = "fixture-csrf"
    client.session.chat_url = chat_url or ORIGIN + CHAT_PATH
    client.session.patient_context_confirmed = True
    return client, conn, budget


def _rows(conn: sqlite3.Connection) -> list[tuple[str, float, float]]:
    found = conn.execute("SELECT state, reserved_usd, incurred_usd FROM agent_spend").fetchall()
    return [(str(r[0]), float(r[1]), float(r[2])) for r in found]


def test_chat_success_incurs_once_and_budget_counts_the_reserve_twice() -> None:
    client, conn, budget = _ledger_client(Wire())
    assert client.post_chat("hello").status == 200
    assert _rows(conn) == [("incurred", RESERVE, RESERVE)]
    assert committed_usd(conn) == pytest.approx(RESERVE)
    assert state(budget) == (pytest.approx(2 * RESERVE), pytest.approx(2 * RESERVE), 1)  # F2


@pytest.mark.parametrize("status", [429, 503, 400])
def test_chat_status_that_billed_nothing_returns_everything(status: int) -> None:
    client, conn, budget = _ledger_client(Wire(Response(status, b"", headers={"Retry-After": "3"})))
    with pytest.raises(TargetStatusError):
        client.post_chat("hello")
    assert _rows(conn) == [("released", 0.0, 0.0)]
    assert committed_usd(conn) == 0.0
    assert state(budget) == (0.0, 0.0, 0)


def test_chat_gate_refusal_before_budget_returns_everything() -> None:
    wire = Wire()
    client, conn, budget = _ledger_client(wire, chat_url="https://evil.example/chat.php")
    with pytest.raises(RefusedByChokepoint):
        client.post_chat("hello")
    assert wire.calls == []
    assert committed_usd(conn) == 0.0
    assert state(budget) == (0.0, 0.0, 0)


def test_chat_spend_limit_refusal_zeroes_the_ledger_but_budget_keeps_the_estimate() -> None:
    wire = Wire()
    client, conn, budget = _ledger_client(wire, attestations=[])
    with pytest.raises(RefusedByChokepoint):
        client.post_chat("hello")
    assert wire.calls == []
    assert committed_usd(conn) == 0.0
    assert state(budget) == (RESERVE, RESERVE, 0)  # F1: conservative leftover in Budget only


def test_p_u_post_dispatch_transport_failure_holds_the_ledger_reservation() -> None:
    """A dispatched chat whose outcome is unknown stays reserved. Releasing it at $0 was the undercount."""
    wire = Wire(error=ConnectionResetError(54, "reset after write"))
    client, conn, _budget = _ledger_client(wire)
    with pytest.raises(SessionError, match="transport failed"):
        client.post_chat("hello")
    assert [m for m, _u in wire.calls] == ["POST"]  # the chat request did leave the process
    assert _rows(conn) == [("reserved", RESERVE, 0.0)]
    assert committed_usd(conn) == pytest.approx(RESERVE)


def test_journal_path_holds_the_reservation_on_the_same_failure() -> None:
    """The correct behavior, for contrast with F4: a post-dispatch OSError stays reserved as `unknown`."""
    conn, _ledger, journal = p6_env()
    p6_campaign(conn)

    def send() -> Outcome:
        raise ConnectionResetError(54, "reset after write")

    with pytest.raises(UnknownOutcome):
        dispatch(
            journal, "corr-p6", 1, 0, role="executor", kind="target", intent="turn-1", reserve_usd=RESERVE, send=send
        )
    assert _rows(conn) == [("reserved", RESERVE, 0.0)]
    assert committed_usd(conn) == pytest.approx(RESERVE)
    row = journal.latest("corr-p6", 1)
    assert row is not None and row.state == "unknown"


# ---------------------------------------------------------------------------------------------------------------
# F3: restart re-seed and the lifetime nature of the caps
# ---------------------------------------------------------------------------------------------------------------
def _spend(conn: sqlite3.Connection, call_id: str, usd: float, *, incur: bool) -> None:
    ledger = Ledger(conn, p6_budget())
    ledger.reserve(call_id, "target", usd)
    if incur:
        ledger.incur(call_id, usd)


def test_restart_reseeds_budget_from_incurred_and_open_reservations() -> None:
    conn = p6_store()
    _spend(conn, "a", 0.05, incur=True)
    _spend(conn, "b", 0.02, incur=False)  # an open reservation from a process that no longer exists
    caps = p6_caps()
    budget = load_shared_budget(conn, caps, approval_token(caps, P6_SECRET), P6_SECRET)
    assert state(budget) == (pytest.approx(0.07), pytest.approx(0.07), 0)


def test_restart_refuses_when_committed_spend_exceeds_a_cap() -> None:
    conn = p6_store()
    _spend(conn, "a", 0.05, incur=True)
    caps = Caps(0.04, 5.0, 50, 5.0, 15.0)
    with pytest.raises(BudgetExceeded):
        load_shared_budget(conn, caps, approval_token(caps, P6_SECRET), P6_SECRET)


def test_per_day_total_is_never_reset_so_it_is_not_a_daily_cap() -> None:
    budget = p6_budget()
    budget.reserve(1.0, attack=False)
    budget.start_run()
    assert (budget.run_spent, budget.day_spent) == (0.0, 1.0)


def test_released_ledger_rows_do_not_count_toward_the_committed_total() -> None:
    conn = p6_store()
    ledger = Ledger(conn, p6_budget())
    ledger.reserve("a", "target", 0.05)
    ledger.release("a")
    assert committed_usd(conn) == 0.0


# ---------------------------------------------------------------------------------------------------------------
# F5: provider-model (OpenRouter judge) paths. A fake transport and a canary value, never a real key.
# ---------------------------------------------------------------------------------------------------------------
def _provider(monkeypatch: pytest.MonkeyPatch, response: Response | None, error: Exception | None = None) -> OpenRouterJudgeModel:
    monkeypatch.setenv("OPENROUTER_API_KEY", "canary-not-a-real-key")

    def transport(method: str, url: str, headers: object = None, body: object = None, timeout: float = 0.0) -> Response:
        if error is not None:
            raise error
        assert response is not None
        return response

    return OpenRouterJudgeModel("test/model", transport=transport)


def _completion(content: str, cost: float | None) -> Response:
    import json

    payload: dict[str, object] = {"choices": [{"message": {"content": content}}]}
    if cost is not None:
        payload["usage"] = {"cost": cost}
    return Response(200, json.dumps(payload).encode())


def test_provider_valid_label_records_the_reported_cost(monkeypatch: pytest.MonkeyPatch) -> None:
    model = _provider(monkeypatch, _completion("pass", 0.0003))
    assert model.complete("transcript") == "pass"
    assert model.last_cost_usd == pytest.approx(0.0003)


def test_provider_invalid_label_still_exposes_the_bill(monkeypatch: pytest.MonkeyPatch) -> None:
    model = _provider(monkeypatch, _completion("maybe", 0.0003))
    with pytest.raises(OpenRouterLabelError):
        model.complete("transcript")
    assert model.last_cost_usd == pytest.approx(0.0003)


def test_provider_missing_usage_is_none_not_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    model = _provider(monkeypatch, _completion("pass", None))
    model.complete("transcript")
    assert model.last_cost_usd is None


@pytest.mark.parametrize("status", [429, 503])
def test_provider_http_failure_reports_no_cost(monkeypatch: pytest.MonkeyPatch, status: int) -> None:
    model = _provider(monkeypatch, Response(status, b"{}"))
    with pytest.raises(OpenRouterHttpError):
        model.complete("transcript")
    assert model.last_cost_usd is None


@pytest.mark.parametrize("status", [500, 502, 504])
def test_provider_unknown_status_holds_rather_than_reporting_a_bill(monkeypatch: pytest.MonkeyPatch, status: int) -> None:
    model = _provider(monkeypatch, Response(status, b"{}"))
    with pytest.raises(ProviderOutcomeUnknown):
        model.complete("transcript")
    assert model.last_cost_usd is None


def test_provider_transport_error_reports_no_cost(monkeypatch: pytest.MonkeyPatch) -> None:
    model = _provider(monkeypatch, None, error=ConnectionResetError(54, "reset"))
    with pytest.raises(ProviderOutcomeUnknown):
        model.complete("transcript")
    assert model.last_cost_usd is None


def test_provider_disabled_refuses_before_the_key_or_the_real_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    import agentforge.providers.transport as transport_module

    def must_not_run(*_a: object, **_k: object) -> object:
        raise AssertionError("the real provider transport was called")

    monkeypatch.setattr(transport_module, "provider_transport", must_not_run)
    monkeypatch.setenv("OPENROUTER_API_KEY", "canary-not-a-real-key")
    with pytest.raises(RefusedByChokepoint) as caught:
        OpenRouterJudgeModel("test/model").complete("transcript")
    assert caught.value.gate == "provider"


def test_provider_calls_take_no_ledger_so_recording_the_bill_is_the_callers_job() -> None:
    parameters = inspect.signature(OpenRouterJudgeModel.__init__).parameters
    assert not {"ledger", "budget"} & set(parameters)
    assert openrouter_module.PROVIDER_ENABLED is False


# ---------------------------------------------------------------------------------------------------------------
# F6: a post-dispatch provider failure holds the Judge reservation. Injected transport only. No flag is changed.
# ---------------------------------------------------------------------------------------------------------------
def _judge_with(monkeypatch: pytest.MonkeyPatch, error: Exception) -> tuple[Any, Any]:
    from test_p4_judge import _judge, _ledger

    def transport(method: str, url: str, headers: object = None, body: object = None, timeout: float = 0.0) -> Response:
        raise error

    monkeypatch.setenv("OPENROUTER_API_KEY", "canary-not-a-real-key")
    _conn, ledger = _ledger()
    judge = _judge(ledger=ledger, stub=OpenRouterJudgeModel("m/x", transport=transport), reserve_usd=0.01)
    return judge, ledger


@pytest.mark.parametrize("error", [TimeoutError("timed out"), ConnectionResetError(54, "reset after write")])
def test_f6_provider_failure_after_dispatch_holds_the_judge_reservation(
    monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    """The request was handed to the transport. Whether it billed is unknown, so the reservation is held in full."""
    from test_p4_judge import _result, _transcript

    judge, ledger = _judge_with(monkeypatch, error)
    outcome = judge.judge_transcript(
        _result(subcategory="TM-SC-1"), _transcript("workflow only", transcript_id="rec-f6")
    )
    assert outcome["error_code"] == "judge_timeout" and outcome["retryable"] is True
    assert ledger.totals("judge").reserved_usd == 0.01
    assert ledger.totals("judge").incurred_usd == 0
