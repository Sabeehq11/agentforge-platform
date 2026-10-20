"""One correlation ID through Orchestrator, Red Team, executor and Judge. Documentation is not traced."""

from __future__ import annotations

import pytest
from fixtures import DISTINCT_TEXTS, FakeTarget, ScriptedModel, answer, model_json, p6_campaign, p6_env
from agentforge.agents.judge import RulesJudge, StubJudgeModel
from agentforge.agents.red_team_generator import RedTeamGenerator
from agentforge.contracts.validate import ContractError
from agentforge.evals.cases import load_cases
from agentforge.evals.login import LoginRequest
from agentforge.orchestrator.loop import CampaignLoop
from agentforge.orchestrator.policy import load_config
from agentforge.orchestrator.sequence import SequenceRunner
from agentforge.orchestrator.trace import P6_ROLES, trace

CID = "corr-p6"


def _loop(conn, ledger, journal, replies):  # type: ignore[no-untyped-def]
    config = load_config()
    seeds = load_cases()
    model = ScriptedModel(replies)
    generator = RedTeamGenerator(
        conn, journal, config, model, seeds, alloc_step=iter(range(1, 200)).__next__, sleep=lambda _s: None,
        reserve_usd=0.0,
    )
    target = FakeTarget([answer("I will not follow that instruction.")])
    runner = SequenceRunner(
        conn, journal, config, p6_client(target, ledger),  # type: ignore[name-defined]
        LoginRequest("copilot_doc_a", "not-committed"), "100", sleep=lambda _s: None, request_cap=5,
    )
    judge = RulesJudge(
        "config/models.yaml", ledger, stub=StubJudgeModel(), canaries={"TM-PI-1": "CANARY-AF-PI1"}, fixture_only=True
    )
    return CampaignLoop(conn, journal, config, generator, runner, judge, seeds, observed_pin="9f03654"), target


def p6_client(target, ledger):  # type: ignore[no-untyped-def]
    from fixtures import p6_client as build

    return build(target, ledger, ledger._budget)


def test_one_correlation_id_reaches_every_p6_role_and_not_documentation() -> None:
    conn, ledger, journal = p6_env()
    p6_campaign(conn, CID, attack_count_cap=1)
    loop, target = _loop(conn, ledger, journal, [model_json(DISTINCT_TEXTS[0])])
    outcome = loop.run(CID)
    assert outcome.phase == "done" and outcome.sequences == 1
    found = trace(conn, CID)
    assert found["documentation_present"] is False
    assert found["roles"] == P6_ROLES
    assert "documentation" not in found["roles"]
    assert all(row["role"] != "documentation" for row in found["run_logs"])
    logged = {row["role"] for row in found["run_logs"]}
    assert {"orchestrator", "red_team", "judge", "harness"} <= logged
    ids = {row[0] for row in conn.execute("SELECT correlation_id FROM dispatch_journal")}
    assert ids == {CID}
    assert target.calls and "login.php" in target.calls[0][1]


def test_a_mismatched_correlation_id_halts_with_a_contract_error() -> None:
    conn, ledger, journal = p6_env()
    request = p6_campaign(conn, CID, attack_count_cap=1)
    request["correlation_id"] = "corr-other"
    config = load_config()
    generator = RedTeamGenerator(
        conn, journal, config, ScriptedModel([model_json(DISTINCT_TEXTS[0])]), load_cases(),
        alloc_step=iter(range(1, 20)).__next__, sleep=lambda _s: None, reserve_usd=0.0,
    )
    real = generator.generate  # type: ignore[method-assign]

    def swapped(req, mode, **kwargs):  # type: ignore[no-untyped-def]
        made = real({**req, "correlation_id": CID}, mode, **kwargs)
        made.attack = {**made.attack, "correlation_id": "corr-other"}
        return made

    generator.generate = swapped  # type: ignore[method-assign]
    loop, _target = _loop(conn, ledger, journal, [model_json(DISTINCT_TEXTS[0])])
    loop._generator = generator
    with pytest.raises(ContractError):
        loop.run(CID)
