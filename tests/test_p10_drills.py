"""P10 failure drills. Each typed error comes from an existing handler, not a hand-built envelope.

No socket. No gitignored ledger. Temporary store only.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fixtures import p6_budget, p6_campaign, p6_env

from agentforge.agents.judge import RulesJudge, StubJudgeModel
from agentforge.agents.red_team import SeedMutator, _budget_error
from agentforge.contracts.validate import ContractError, validate
from agentforge.evals.cases import load_cases
from agentforge.orchestrator.journal import Refused
from agentforge.orchestrator.loop import CampaignLoop  # noqa: F401 — constructed by _loop
from agentforge.orchestrator.policy import RetryPolicy
from agentforge.orchestrator.retry import StepHalt, classify_refusal, run_step
from agentforge.safety.budget import BudgetExceeded
from agentforge.safety.ledger import SHARED_CEILING_USD, Ledger, LedgerError
from tests.test_p4_judge import _campaign, _transcript
from tests.test_p6_ratelimit import NOW, Sleeps, _sender, _step
from tests.test_p7_loop import _loop

from agentforge.safety.chokepoint import Response

CID = "corr-p10-drill"
CODES = ("target_unreachable", "budget_exceeded", "judge_timeout")
DRILLS = Path(__file__).resolve().parents[1] / "evals" / "results" / "drills-p10.json"


def _halt_reason(conn) -> str:  # type: ignore[no-untyped-def]
    row = conn.execute("SELECT halt_reason FROM campaigns WHERE correlation_id = ?", (CID,)).fetchone()
    assert row is not None
    return str(row[0])


def test_unverified_identity_halts_target_unreachable_and_sends_nothing() -> None:
    conn, ledger, journal = p6_env()
    p6_campaign(conn, CID, attack_count_cap=1)
    loop = _loop(conn, ledger, journal, [], stub=None)
    loop._identity_verified = False  # noqa: SLF001
    with pytest.raises(ContractError, match="identity_mismatch"):
        loop._check_identity(CID, {"target_pin": "9f03654"})  # noqa: SLF001
    assert _halt_reason(conn) == "target_unreachable"
    assert journal.rows(CID) == []


def test_unknown_outcome_on_resume_halts_target_unreachable() -> None:
    conn, ledger, journal = p6_env()
    p6_campaign(conn, CID, attack_count_cap=1)
    loop = _loop(conn, ledger, journal, [], stub=None, observed_pin="9f03654")
    from agentforge.orchestrator.state import halt

    halt(conn, CID, "target_unreachable", "retryable halt", retryable=True)
    journal.intend(CID, 1, 0, role="executor", kind="target", intent="turn", reserve_usd=0.0)
    sent = journal.latest(CID, 1)
    assert sent is not None
    journal.mark_sent(sent.call_id)
    outcome = loop.resume(CID)
    assert outcome.error_code == "target_unreachable"
    assert _halt_reason(conn) == "target_unreachable"


def test_non_budget_refusal_and_non_retryable_status_halt_target_unreachable() -> None:
    halt = classify_refusal(Refused("allowlist", "off list"))
    assert halt.code == "target_unreachable"
    assert halt.retryable is False

    conn, _ledger, journal = p6_env()
    p6_campaign(conn)
    from tests.fixtures import ScriptedTransport

    transport = ScriptedTransport([Response(500, b"down")])
    sleeps = Sleeps()
    with pytest.raises(StepHalt) as caught:
        _step(journal, conn, sleeps, _sender(transport))
    assert caught.value.halt.code == "target_unreachable"
    assert sleeps.calls == []


def test_budget_reserve_and_ledger_reserve_refuse_before_any_transport() -> None:
    budget = p6_budget(max_attacks=1, per_run=0.05)
    budget.reserve(0.05, attack=True)
    with pytest.raises(BudgetExceeded):
        budget.reserve(0.01, attack=True)
    assert budget.attacks == 1

    conn, ledger, _journal = p6_env(max_attacks=1)
    ledger.reserve("call-1", "red_team", 0.0)
    with pytest.raises(BudgetExceeded):
        ledger.reserve("call-2", "red_team", 0.0)
    row = conn.execute("SELECT call_id FROM agent_spend WHERE call_id = 'call-2'").fetchone()
    assert row is None

    ledger.release("call-1")
    released = conn.execute("SELECT state, incurred_usd FROM agent_spend WHERE call_id = 'call-1'").fetchone()
    assert released == ("released", 0.0)
    with pytest.raises(LedgerError):
        ledger.combined("call-1")

    envelope = _budget_error(CID, "per-run cap would be exceeded")
    validate("budget_exceeded", envelope)
    assert envelope["error_code"] == "budget_exceeded"

    conn2, ledger2, journal2 = p6_env()
    p6_campaign(conn2, CID, attack_count_cap=1)
    loop = _loop(conn2, ledger2, journal2, [], stub=None)
    from agentforge.orchestrator.sequence import PreflightRefused

    class _Refusing:
        def run(self, correlation_id: str, turns: object, transcript_id: str) -> object:
            raise PreflightRefused("per-run cap would be exceeded")

    loop._runner = _Refusing()  # type: ignore[assignment]  # noqa: SLF001
    generated = type("G", (), {"attack": {"correlation_id": CID}, "turns": (), "model_call_id": "m"})()
    outcome = loop._execute_and_judge(CID, generated)  # noqa: SLF001
    assert outcome is not None and outcome.error_code == "budget_exceeded"
    assert _halt_reason(conn2) == "budget_exceeded"


def test_shared_ceiling_refuses_the_next_reserve_and_writes_nothing() -> None:
    """Ledger.reserve is the safety path. A temporary store is filled to $5. The gitignored ledger is not opened.

    The role is judge so the per-run attack cap is not what refuses the call. The $5 fill is one reservation,
    so the per-run dollar cap is not what refuses the next cent.
    """
    conn, ledger, _journal = p6_env()
    ledger.reserve("p10-ceiling-open", "judge", SHARED_CEILING_USD)
    with pytest.raises(BudgetExceeded, match="shared ceiling would be exceeded"):
        ledger.reserve("p10-ceiling-refused", "judge", 0.01)
    refused = conn.execute(
        "SELECT call_id FROM agent_spend WHERE call_id = 'p10-ceiling-refused'"
    ).fetchone()
    assert refused is None
    assert conn.execute("SELECT COALESCE(SUM(incurred_usd), 0) FROM agent_spend").fetchone()[0] == 0
    ledger.release("p10-ceiling-open")
    released = conn.execute(
        "SELECT state, incurred_usd FROM agent_spend WHERE call_id = 'p10-ceiling-open'"
    ).fetchone()
    assert released == ("released", 0.0)


def test_attack_count_cap_returns_the_budget_exceeded_envelope() -> None:
    conn, ledger, _journal = p6_env(max_attacks=0)
    seeds = {case.category: case for case in load_cases()}
    mutator = SeedMutator(ledger, seeds, reserve_usd=0.0)
    request = _campaign()
    request["correlation_id"] = CID
    envelope = mutator.propose(request)
    assert envelope["error_code"] == "budget_exceeded"
    validate("budget_exceeded", envelope)
    assert conn.execute("SELECT COUNT(*) FROM agent_spend").fetchone()[0] == 0


def test_judge_timeout_releases_the_reservation() -> None:
    conn, ledger, _journal = p6_env()
    stub = StubJudgeModel(timeout_ids=frozenset({"rec-p10-timeout"}))
    judge = RulesJudge("config/models.yaml", ledger, stub=stub, reserve_usd=0.01, fixture_only=True)
    result = {
        "message_id": "m-p10",
        "correlation_id": CID,
        "schema_version": "v1",
        "produced_at": "2026-10-20T00:00:00Z",
        "category": "TM-SC",
        "subcategory": "TM-SC-1",
        "input_sequence": {"channel": "chat", "turns": [{"role": "user", "content": "synthetic"}]},
        "expected_safe_behavior": "refuse",
        "observed_behavior": "partial",
        "severity": "low",
        "exploitability": "low",
        "regression_flag": False,
    }
    transcript = _transcript("workflow only", transcript_id="rec-p10-timeout")
    transcript["correlation_id"] = CID
    outcome = judge.judge_transcript(result, transcript)  # type: ignore[arg-type]
    assert outcome["error_code"] == "judge_timeout"
    assert outcome["detail"] == "needs_human_review"
    assert outcome["retryable"] is True
    validate("judge_timeout", outcome)
    assert ledger.totals("judge").incurred_usd == 0
    state = conn.execute("SELECT state FROM agent_spend").fetchone()
    assert state is not None and state[0] == "released"


def test_retry_step_does_not_need_a_live_flag() -> None:
    """run_step on an injected 500 is the drill transport. It does not read LIVE_ENABLED."""
    policy = RetryPolicy(max_attempts_per_step=1, max_attempts_per_campaign=1, base_delay_s=1.0, max_delay_s=30.0)
    conn, _ledger, journal = p6_env()
    p6_campaign(conn)
    from tests.fixtures import ScriptedTransport

    with pytest.raises(StepHalt) as caught:
        run_step(
            journal, conn, policy, "corr-p6", 1, role="executor", kind="target", intent="turn", reserve_usd=0.0,
            make_send=_sender(ScriptedTransport([Response(404, b"missing")])), sleep=Sleeps(), clock=lambda: NOW,
        )
    assert caught.value.halt.code == "target_unreachable"


def test_drill_file_records_the_three_envelopes() -> None:
    """The committed drill file is the secret-free record of the three handler results."""
    body = json.loads(DRILLS.read_text(encoding="utf-8"))
    assert body["live"] is False
    codes = [item["error_code"] for item in body["envelopes"]]
    assert codes == list(CODES)
    for item in body["envelopes"]:
        validate(item["error_code"], item)
        assert "transcript" not in json.dumps(item).lower() or item["error_code"] == "judge_timeout"


