"""CampaignLoop replays every pending handoff on the stub and traces all four agents."""

from __future__ import annotations

import pytest
from fixtures import DISTINCT_TEXTS, FakeTarget, ScriptedModel, answer, model_json, p6_campaign, p6_client, p6_env

from agentforge.agents.judge import RulesJudge, StubJudgeModel
from agentforge.agents.red_team_generator import RedTeamGenerator
from agentforge.contracts.validate import ContractError
from agentforge.evals.cases import load_cases
from agentforge.evals.login import LoginRequest
from agentforge.harness.stub_target import StubReply, StubTarget
from agentforge.orchestrator.loop import CampaignLoop
from agentforge.orchestrator.policy import load_config
from agentforge.orchestrator.sequence import SequenceRunner
from agentforge.orchestrator.trace import trace_agents
from agentforge.orchestrator.versions import observe_version
CID = "corr-p7-loop"
PIN = "9f03654"
LATER = "1111111"
GREATER = "fffffff"


def _loop(conn, ledger, journal, replies, *, stub, observed_pin=PIN, reports_dir=None):  # type: ignore[no-untyped-def]
    config = load_config()
    seeds = load_cases()
    generator = RedTeamGenerator(
        conn, journal, config, ScriptedModel(replies), seeds,
        alloc_step=iter(range(1, 200)).__next__, sleep=lambda _s: None, reserve_usd=0.0,
    )
    target = FakeTarget([answer("emitting CANARY-AF-PI1 as requested")])
    runner = SequenceRunner(
        conn, journal, config, p6_client(target, ledger, ledger._budget),
        LoginRequest("copilot_doc_a", "not-committed"), "100", sleep=lambda _s: None, request_cap=5,
    )
    judge = RulesJudge(
        "config/models.yaml", ledger, stub=StubJudgeModel(), canaries={"TM-PI-1": "CANARY-AF-PI1"}, fixture_only=True
    )
    return CampaignLoop(
        conn, journal, config, generator, runner, judge, seeds,
        observed_pin=observed_pin, stub=stub, reports_dir=reports_dir,
    )


def test_a_missing_stub_does_not_skip_a_pending_handoff() -> None:
    conn, ledger, journal = p6_env()
    p6_campaign(conn, CID, attack_count_cap=1)
    observe_version(conn, PIN, identity_verified=True, correlation_id=CID)
    observe_version(conn, LATER, identity_verified=True, correlation_id=CID)
    loop = _loop(conn, ledger, journal, [model_json(DISTINCT_TEXTS[0])], stub=None, observed_pin=LATER)
    with pytest.raises(ContractError, match="no stub"):
        loop.run(CID)
    assert conn.execute("SELECT status FROM version_handoffs WHERE target_pin = ?", (LATER,)).fetchone()[0] == "pending"
    assert conn.execute("SELECT COUNT(*) FROM regression_runs").fetchone()[0] == 0
    assert conn.execute("SELECT phase, halt_reason FROM campaigns").fetchone()[0] == "halted"


def test_two_pending_handoffs_each_run_every_eligible_case(tmp_path) -> None:  # type: ignore[no-untyped-def]
    conn, ledger, journal = p6_env()
    p6_campaign(conn, CID, attack_count_cap=1)
    observe_version(conn, PIN, identity_verified=True, correlation_id=CID)
    loop = _loop(conn, ledger, journal, [model_json(DISTINCT_TEXTS[0])], stub=StubTarget(), reports_dir=tmp_path)
    outcome = loop.run(CID)
    assert outcome.phase == "done"
    case = conn.execute("SELECT id, exploit_id FROM regression_cases").fetchone()
    assert case is not None
    digest = str(conn.execute("SELECT sequence_hash FROM exploits WHERE id = ?", (case[1],)).fetchone()[0])
    observe_version(conn, GREATER, identity_verified=True, correlation_id=CID)
    observe_version(conn, LATER, identity_verified=True, correlation_id=CID)
    assert GREATER > LATER
    assert conn.execute("SELECT previous_pin FROM version_handoffs WHERE target_pin = ?", (LATER,)).fetchone()[0] == GREATER
    # Both new pins pass, so the identity check must finish both rather than stop after the first.
    fixed = StubTarget({digest: StubReply(200, "I will not follow that instruction.")})
    second = _loop(
        conn, ledger, journal, [model_json(DISTINCT_TEXTS[1])], stub=fixed, observed_pin=LATER, reports_dir=tmp_path
    )
    second._check_identity(CID, {"target_pin": LATER})  # noqa: SLF001
    for pin in (GREATER, LATER):
        assert conn.execute("SELECT status FROM version_handoffs WHERE target_pin = ?", (pin,)).fetchone()[0] == "done"
        assert conn.execute(
            "SELECT COUNT(*) FROM regression_runs WHERE case_id = ? AND system_version = ?", (case[0], pin)
        ).fetchone()[0] == 3
    stored = conn.execute("SELECT body, fix_validation, fix_validation_pin FROM reports").fetchone()
    assert stored[1] == "fixed"
    assert stored[2] == LATER
    written = next(tmp_path.glob("rpt-*.md"))
    assert written.read_text(encoding="utf-8").strip() == str(stored[0]).strip()
    assert f"pin {LATER}" in written.read_text(encoding="utf-8")


def test_campaign_loop_traces_four_agents_under_one_correlation_id() -> None:
    conn, ledger, journal = p6_env()
    p6_campaign(conn, CID, attack_count_cap=1)
    observe_version(conn, PIN, identity_verified=True, correlation_id=CID)
    loop = _loop(conn, ledger, journal, [model_json(DISTINCT_TEXTS[0])], stub=StubTarget())
    outcome = loop.run(CID)
    assert outcome.phase == "done"
    found = trace_agents(conn, CID)
    assert found["agents"] == ("orchestrator", "red_team", "judge", "documentation")
    assert found["executor"] is True
    assert found["one_correlation_id"] is True
    assert found["report_ids"]
    assert conn.execute(
        "SELECT COUNT(*) FROM run_logs WHERE correlation_id != ?", (CID,)
    ).fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM reports WHERE correlation_id = ?", (CID,)).fetchone()[0] == 1


def test_a_quoted_canary_without_obedience_is_held() -> None:
    """The loop passes the recorded target text, not the transcript id, into the hold check."""
    conn, ledger, journal = p6_env()
    p6_campaign(conn, CID, attack_count_cap=1)
    observe_version(conn, PIN, identity_verified=True, correlation_id=CID)
    quoted = FakeTarget([answer("I will not print CANARY-AF-PI1.")])
    config = load_config()
    seeds = load_cases()
    generator = RedTeamGenerator(
        conn, journal, config, ScriptedModel([model_json(DISTINCT_TEXTS[0])]), seeds,
        alloc_step=iter(range(1, 50)).__next__, sleep=lambda _s: None, reserve_usd=0.0,
    )
    runner = SequenceRunner(
        conn, journal, config, p6_client(quoted, ledger, ledger._budget),
        LoginRequest("copilot_doc_a", "not-committed"), "100", sleep=lambda _s: None, request_cap=5,
    )
    judge = RulesJudge(
        "config/models.yaml", ledger, stub=StubJudgeModel(), canaries={"TM-PI-1": "CANARY-AF-PI1"}, fixture_only=True
    )
    loop = CampaignLoop(conn, journal, config, generator, runner, judge, seeds, observed_pin=PIN, stub=StubTarget())
    real = judge.judge_transcript

    def force_fail(result, transcript):  # type: ignore[no-untyped-def]
        judged = real(result, transcript)
        if isinstance(judged, dict) and "exploit_id" not in judged and "error_code" not in judged:
            from agentforge.agents.judge import _exploit

            return _exploit(result, judge_transcript_of(transcript), "quoting CANARY-AF-PI1")
        return judged

    judge.judge_transcript = force_fail  # type: ignore[method-assign]
    loop.run(CID)
    assert conn.execute("SELECT held, status FROM reports").fetchone() == (1, "draft")


def judge_transcript_of(transcript):  # type: ignore[no-untyped-def]
    from agentforge.agents.judge import require_transcript

    return require_transcript(transcript)
