"""Identity is the first target call, and a mismatch sends nothing later."""

from __future__ import annotations

from fixtures import DISTINCT_TEXTS, FakeTarget, ScriptedModel, answer, model_json, p6_campaign, p6_client, p6_env
from agentforge.agents.judge import RulesJudge, StubJudgeModel
from agentforge.agents.red_team_generator import RedTeamGenerator
from agentforge.contracts.validate import ContractError
from agentforge.evals.cases import load_cases
from agentforge.evals.login import LoginRequest
from agentforge.orchestrator.loop import CampaignLoop
from agentforge.orchestrator.policy import load_config
from agentforge.orchestrator.sequence import SequenceRunner

CID = "corr-p6"


def _run(verified: bool, login_body: bytes = b"OpenEMR login") -> tuple[object, FakeTarget]:
    conn, ledger, journal = p6_env()
    p6_campaign(conn, CID, attack_count_cap=1)
    config = load_config()
    seeds = load_cases()
    generator = RedTeamGenerator(
        conn, journal, config, ScriptedModel([model_json(DISTINCT_TEXTS[0])]), seeds,
        alloc_step=iter(range(1, 50)).__next__, sleep=lambda _s: None, reserve_usd=0.0,
    )
    target = FakeTarget([answer("refused")], login_body=login_body)
    runner = SequenceRunner(
        conn, journal, config, p6_client(target, ledger, ledger._budget),
        LoginRequest("copilot_doc_a", "not-committed"), "100", sleep=lambda _s: None, request_cap=1,
    )
    judge = RulesJudge("config/models.yaml", ledger, stub=StubJudgeModel(), fixture_only=True)
    loop = CampaignLoop(conn, journal, config, generator, runner, judge, seeds, identity_verified=verified)
    return loop, target


def test_identity_check_is_the_first_target_call() -> None:
    loop, target = _run(True)
    outcome = loop.run(CID)  # type: ignore[attr-defined]
    assert outcome.phase == "done"
    assert target.calls
    assert "login.php" in target.calls[0][1]


def test_an_unverified_identity_sends_nothing() -> None:
    loop, target = _run(False)
    try:
        loop.run(CID)  # type: ignore[attr-defined]
    except ContractError:
        pass
    assert target.calls == []


def test_resume_rechecks_a_live_target_and_skips_the_network_for_a_fixture() -> None:
    """A fixture resume reconciles without a socket. A live client is re-checked before any later target call."""
    conn, ledger, journal = p6_env()
    p6_campaign(conn, CID, attack_count_cap=1)
    config = load_config()
    seeds = load_cases()
    generator = RedTeamGenerator(
        conn, journal, config, ScriptedModel([model_json(DISTINCT_TEXTS[0])]), seeds,
        alloc_step=iter(range(1, 50)).__next__, sleep=lambda _s: None, reserve_usd=0.0,
    )
    target = FakeTarget([answer("refused")])
    runner = SequenceRunner(
        conn, journal, config, p6_client(target, ledger, ledger._budget),
        LoginRequest("copilot_doc_a", "not-committed"), "100", sleep=lambda _s: None, request_cap=1,
    )
    judge = RulesJudge("config/models.yaml", ledger, stub=StubJudgeModel(), fixture_only=True)
    loop = CampaignLoop(conn, journal, config, generator, runner, judge, seeds, observed_pin="9f03654")
    from agentforge.orchestrator.state import halt

    halt(conn, CID, "target_unreachable", "retryable halt", retryable=True)
    gets_before = sum(1 for method, url in target.calls if method == "GET" and "login.php" in url)
    outcome = loop.resume(CID)
    gets_after = sum(1 for method, url in target.calls if method == "GET" and "login.php" in url)
    assert outcome.phase == "done"
    # Reconciliation itself sends nothing. The one new identity GET is the next sequence setup, not a live re-check.
    assert gets_after == gets_before + 1

    class _Live:
        fake_transport = False
        calls = 0

        def verify_identity(self) -> None:
            self.calls += 1
            raise RuntimeError("fingerprint mismatch")

    live = _Live()
    runner._client = live  # type: ignore[assignment]
    halt(conn, CID, "target_unreachable", "retryable halt", retryable=True)
    calls_before = len(target.calls)
    try:
        loop.resume(CID)
    except ContractError as exc:
        assert "identity_mismatch" in str(exc)
    assert live.calls == 1
    assert len(target.calls) == calls_before


def test_a_fingerprint_mismatch_sends_no_later_call() -> None:
    loop, target = _run(True, login_body=b"not the reviewed page")
    outcome = loop.run(CID)  # type: ignore[attr-defined]
    assert outcome.phase == "halted"
    assert outcome.error_code == "target_unreachable"
    assert all("chat.php" not in url for _method, url in target.calls)
