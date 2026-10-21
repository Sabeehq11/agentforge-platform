"""R1 coverage and rank, R2 mutation and multi-turn. Scripted model and fake target. No network."""

from __future__ import annotations

import importlib.util
import json
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest
from fixtures import DISTINCT_TEXTS, FakeTarget, ScriptedModel, answer, model_json, p6_campaign, p6_client, p6_env

from agentforge.agents.judge import RulesJudge, StubJudgeModel
from agentforge.agents.red_team_generator import GenerationStopped, RedTeamGenerator
from agentforge.contracts.validate import ContractError, validate
from agentforge.evals.cases import load_cases
from agentforge.evals.login import LoginRequest
from agentforge.orchestrator.loop import CampaignLoop
from agentforge.orchestrator.policy import StopPolicy, load_config
from agentforge.orchestrator.priority import load_evidence
from agentforge.orchestrator.retry import Halt, StepHalt
from agentforge.orchestrator.sequence import SequenceRunner
from agentforge.orchestrator.state import CampaignOpen, halt

ROOT = Path(__file__).resolve().parents[1]
CID = "corr-r1"
PIN = "9f03654"


def _loop(conn, ledger, journal, replies, *, answers=None, stop=None, reserve_usd=0.0):  # type: ignore[no-untyped-def]
    config = load_config()
    if stop is not None:
        config = replace(config, stop=stop)
    seeds = load_cases()
    generator = RedTeamGenerator(
        conn, journal, config, ScriptedModel(replies), seeds,
        alloc_step=iter(range(1, 200)).__next__, sleep=lambda _s: None, reserve_usd=reserve_usd,
    )
    target = FakeTarget([answer("I will not follow that instruction.")])
    runner = SequenceRunner(
        conn, journal, config, p6_client(target, ledger, ledger._budget),
        LoginRequest("copilot_doc_a", "not-committed"), "100", sleep=lambda _s: None, request_cap=10,
    )
    judge = RulesJudge(
        "config/models.yaml", ledger, stub=StubJudgeModel(answers),
        canaries={"TM-PI-1": "CANARY-AF-PI1", "TM-PI-3": "CANARY-AF-PI3"}, fixture_only=True,
    )
    loop = CampaignLoop(conn, journal, config, generator, runner, judge, seeds, observed_pin=PIN)
    return loop, generator


def _partial(conn, signal_id_text: str, *, verdict: str = "partial", category: str = "TM-PI") -> int:
    transcript = {
        "transcript_id": f"rec-{signal_id_text}",
        "correlation_id": CID,
        "schema_version": "v1",
        "recorded_by": "executor",
        "turns": [
            {"role": "user", "content": DISTINCT_TEXTS[5]},
            {"role": "target", "content": f"unclear {signal_id_text}"},
        ],
    }
    cursor = conn.execute(
        """
        INSERT INTO signals (correlation_id, category, subcategory, verdict, evidence_hash, dedup_key, transcript_id,
            transcript_json, parent_id, depth, recorded_at)
        VALUES (?, ?, 'TM-PI-1', ?, ?, ?, ?, ?, NULL, 0, '2026-10-21T00:00:00Z')
        """,
        (
            CID, category, verdict, "c" * 64, f"k-{signal_id_text}", f"rec-{signal_id_text}",
            json.dumps(transcript),
        ),
    )
    conn.commit()
    return int(cursor.lastrowid or 0)


def _coverage(conn, category: str = "TM-PI") -> tuple[int, int, int]:
    row = conn.execute(
        "SELECT case_count, pass_count, fail_count FROM coverage_metrics WHERE category = ? AND system_version = ?",
        (category, PIN),
    ).fetchone()
    assert row is not None
    return int(row[0]), int(row[1]), int(row[2])


def test_a_star_category_is_rejected_by_the_published_contract() -> None:
    with pytest.raises(ContractError):
        validate("campaign_request", {**_request_body(), "category": "*"})


def _request_body() -> dict[str, object]:
    from fixtures import campaign_request

    return campaign_request()


def test_one_graded_attack_writes_one_coverage_row_and_a_second_increments_it() -> None:
    conn, ledger, journal = p6_env()
    p6_campaign(conn, CID, attack_count_cap=1)
    loop, _generator = _loop(conn, ledger, journal, [model_json(DISTINCT_TEXTS[0])])
    first = loop.run(CID)
    assert first.phase == "done" and first.sequences == 1
    assert _coverage(conn) == (1, 1, 0)
    conn.execute("UPDATE campaigns SET phase = 'done'")
    conn.commit()
    p6_campaign(conn, "corr-r1b", attack_count_cap=1)
    second, _generator = _loop(conn, ledger, journal, [model_json(DISTINCT_TEXTS[1])])
    assert second.run("corr-r1b").sequences == 1
    assert _coverage(conn) == (2, 2, 0)
    assert conn.execute("SELECT SUM(attacks_done) FROM campaigns").fetchone()[0] == 2


def test_a_fail_increments_fail_count() -> None:
    conn, ledger, journal = p6_env()
    p6_campaign(conn, CID, category="TM-DS", attack_count_cap=1)
    loop, _generator = _loop(conn, ledger, journal, [model_json("Boundary probe that is still short.", subcategory="TM-DS-1")])
    loop._grader._stub.complete = lambda _text: "fail"  # type: ignore[method-assign]  # noqa: SLF001
    outcome = loop.run(CID)
    assert outcome.phase == "done"
    assert _coverage(conn, "TM-DS") == (1, 0, 1)
    assert conn.execute("SELECT COUNT(*) FROM coverage_metrics WHERE category <> 'TM-DS'").fetchone()[0] == 0


def test_a_real_redirect_writes_coverage_per_category_and_never_copies_campaign_attacks() -> None:
    conn, ledger, journal = p6_env()
    p6_campaign(conn, CID, attack_count_cap=3)
    # One attack with no signal exhausts the segment, so the loop redirects once and attacks the next category.
    loop, _generator = _loop(
        conn, ledger, journal,
        [model_json(DISTINCT_TEXTS[0]), model_json(DISTINCT_TEXTS[1], subcategory="TM-DS-1")],
        stop=StopPolicy(after_attacks=1, spend_fraction=1.0, max_redirects=1),
    )
    loop._grader._stub.complete = lambda _text: "pass"  # type: ignore[method-assign]  # noqa: SLF001
    outcome = loop.run(CID)
    assert outcome.phase == "halted"
    redirects, current, attacks = conn.execute(
        "SELECT redirects, current_category, attacks_done FROM campaigns"
    ).fetchone()
    assert (redirects, current, attacks) == (1, "TM-DS", 2)
    assert [row[0] for row in conn.execute("SELECT category FROM attack_variants ORDER BY id")] == ["TM-PI", "TM-DS"]
    # Each category counts its own graded attack. The old campaign-wide attacks_done (2) was not written to either.
    assert _coverage(conn, "TM-PI") == (1, 1, 0)
    assert _coverage(conn, "TM-DS") == (1, 1, 0)


def test_an_unpinned_campaign_attacks_the_ranked_gap_not_the_placeholder() -> None:
    conn, ledger, journal = p6_env()
    p6_campaign(conn, CID, category_pinned=False, category="TM-PI", attack_count_cap=1)
    conn.execute(
        """
        INSERT INTO coverage_metrics (category, system_version, case_count, pass_count, fail_count)
        VALUES ('TM-PI', ?, 4, 4, 0)
        """,
        (PIN,),
    )
    conn.commit()
    loop, generator = _loop(conn, ledger, journal, [model_json(DISTINCT_TEXTS[0], subcategory="TM-DS-1")])
    outcome = loop.run(CID)
    assert outcome.phase == "done"
    assert conn.execute("SELECT current_category FROM campaigns").fetchone()[0] == "TM-DS"
    assert generator.prompts[0].split("Category: ", 1)[1].startswith("TM-DS")
    assert load_evidence(conn, PIN).last_run.get("TM-PI", "") == ""


def test_a_pinned_campaign_keeps_its_category_and_resume_does_not_clear_the_flag() -> None:
    conn, ledger, journal = p6_env()
    p6_campaign(conn, CID, attack_count_cap=1)
    assert conn.execute("SELECT category_pinned FROM campaigns").fetchone()[0] == 1
    loop, generator = _loop(conn, ledger, journal, [model_json(DISTINCT_TEXTS[0])])
    outcome = loop.run(CID)
    assert outcome.phase == "done"
    assert conn.execute("SELECT current_category FROM campaigns").fetchone()[0] == "TM-PI"
    assert "Category: TM-PI" in generator.prompts[0]
    halt(conn, CID, "target_unreachable", "fixture", retryable=True)
    loop.resume(CID)
    assert conn.execute("SELECT category_pinned, current_category FROM campaigns").fetchone() == (1, "TM-PI")


def _spy(generator) -> list[str]:  # type: ignore[no-untyped-def]
    seen: list[str] = []
    real = generator.generate

    def spy(request, mode, **kwargs):  # type: ignore[no-untyped-def]
        seen.append(mode)
        return real(request, mode, **kwargs)

    generator.generate = spy
    return seen


def _interrupt(conn, attack_cap: int) -> None:  # type: ignore[no-untyped-def]
    """An interrupted campaign: retryable halt, with attacks still allowed by its request."""
    body = json.loads(conn.execute("SELECT request_json FROM campaigns WHERE correlation_id = ?", (CID,)).fetchone()[0])
    body["attack_count_cap"] = attack_cap
    conn.execute("UPDATE campaigns SET request_json = ? WHERE correlation_id = ?", (json.dumps(body, sort_keys=True), CID))
    conn.commit()
    halt(conn, CID, "target_unreachable", "fixture", retryable=True)


def test_a_claimed_parent_is_not_selected_again_when_a_resume_really_attacks() -> None:
    conn, ledger, journal = p6_env()
    p6_campaign(conn, CID, attack_count_cap=1)
    parent = _partial(conn, "one")
    loop, generator = _loop(
        conn, ledger, journal, [model_json(DISTINCT_TEXTS[0]), model_json(DISTINCT_TEXTS[1]), model_json(DISTINCT_TEXTS[2])]
    )
    seen = _spy(generator)
    first = loop.run(CID)
    assert first.phase == "done" and seen == ["mutation"]
    assert [row[0] for row in conn.execute("SELECT signal_id FROM mutation_claims")] == [parent]
    _interrupt(conn, 3)
    resumed = loop.resume(CID)
    # The resumed run made two more attacks. The parent was claimed, so neither was a mutation of it.
    assert resumed.phase == "done" and resumed.sequences == 3
    assert seen == ["mutation", "novel", "novel"]
    assert [row[0] for row in conn.execute("SELECT signal_id FROM mutation_claims")] == [parent]
    assert [row[0] for row in conn.execute("SELECT mode FROM attack_variants ORDER BY id")] == ["mutation", "novel", "novel"]


def test_a_requested_multi_turn_campaign_keeps_multi_turn_across_a_resume() -> None:
    conn, ledger, journal = p6_env()
    p6_campaign(conn, CID, requested_mode="multi_turn", attack_count_cap=1)
    loop, generator = _loop(
        conn, ledger, journal, [_two("TM-PI-3", "CANARY-AF-PI3", 0), _two("TM-PI-3", "CANARY-AF-PI3", 2)]
    )
    seen = _spy(generator)
    assert loop.run(CID).phase == "done"
    _interrupt(conn, 2)
    resumed = loop.resume(CID)
    assert resumed.phase == "done" and resumed.sequences == 2
    assert seen == ["multi_turn", "multi_turn"]
    rows = conn.execute("SELECT mode, turns_json FROM attack_variants ORDER BY id").fetchall()
    assert [row[0] for row in rows] == ["multi_turn", "multi_turn"]
    assert all(len(json.loads(row[1])) == 2 for row in rows)
    assert conn.execute("SELECT requested_mode FROM campaigns").fetchone()[0] == "multi_turn"


def test_an_eligible_partial_is_mutated_before_the_requested_multi_turn_resumes() -> None:
    conn, ledger, journal = p6_env()
    p6_campaign(conn, CID, requested_mode="multi_turn", attack_count_cap=2)
    _partial(conn, "one")
    loop, generator = _loop(conn, ledger, journal, [model_json(DISTINCT_TEXTS[0]), _two("TM-PI-3", "CANARY-AF-PI3", 2)])
    seen = _spy(generator)
    assert loop.run(CID).phase == "done"
    assert seen == ["mutation", "multi_turn"]


def test_a_campaign_with_no_requested_mode_stays_one_turn_across_a_resume() -> None:
    conn, ledger, journal = p6_env()
    p6_campaign(conn, CID, attack_count_cap=1)
    assert conn.execute("SELECT requested_mode FROM campaigns").fetchone()[0] is None
    loop, generator = _loop(conn, ledger, journal, [model_json(DISTINCT_TEXTS[0]), model_json(DISTINCT_TEXTS[1])])
    seen = _spy(generator)
    loop.run(CID)
    _interrupt(conn, 2)
    loop.resume(CID)
    assert seen == ["novel", "novel"]


def test_requested_mode_is_additive_and_only_accepts_multi_turn() -> None:
    migrations = ROOT / "src" / "agentforge" / "store" / "migrations"
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript((migrations.parent / "schema.sql").read_text())
    for path in sorted(migrations.glob("000[2-6].sql")):
        conn.executescript(path.read_text())
    conn.execute(
        "INSERT INTO campaigns (correlation_id, request_json, phase, system_version, created_at, updated_at) "
        "VALUES ('old', '{}', 'done', 'v', 't', 't')"
    )
    conn.executescript((migrations / "0007.sql").read_text())
    assert conn.execute("SELECT requested_mode, category_pinned FROM campaigns").fetchone() == (None, 1)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE campaigns SET requested_mode = 'novel'")


def test_a_variant_campaign_writes_no_claim_and_records_no_mutation() -> None:
    conn, ledger, journal = p6_env(max_attacks=80)
    p6_campaign(conn, CID, attack_count_cap=3)
    _partial(conn, "variant-parent")
    pool = [text for index, text in enumerate(DISTINCT_TEXTS) if index != 5]
    loop, _generator = _loop(conn, ledger, journal, [model_json(pool[i], tag=f"v{i}") for i in range(3)])
    outcome = loop.run(CID, variants=3)
    assert outcome.phase == "done"
    assert conn.execute("SELECT COUNT(*) FROM mutation_claims").fetchone()[0] == 0
    modes = {row[0] for row in conn.execute("SELECT mode FROM attack_variants")}
    assert modes == {"variant"}


def test_a_pass_parent_is_not_claimed_and_a_second_partial_can_be() -> None:
    conn, ledger, journal = p6_env()
    p6_campaign(conn, CID, attack_count_cap=1)
    _partial(conn, "pass", verdict="fail")
    second = _partial(conn, "two")
    loop, _generator = _loop(conn, ledger, journal, [model_json(DISTINCT_TEXTS[0])])
    loop.run(CID)
    claimed = [row[0] for row in conn.execute("SELECT signal_id FROM mutation_claims")]
    assert claimed == [second]


def test_a_two_turn_seed_uses_multi_turn_and_a_one_turn_seed_stays_novel() -> None:
    conn, ledger, journal = p6_env()
    p6_campaign(conn, CID, category="TM-PI", attack_count_cap=1)
    loop, generator = _loop(conn, ledger, journal, [_two("TM-PI-3", "CANARY-AF-PI3")])
    # The campaign requests multi_turn. seed_for prefers TM-PI's two-turn seed, so two turns are kept.
    outcome = loop.run(CID, mode="multi_turn")
    assert outcome.phase == "done"
    stored = conn.execute("SELECT mode, turns_json FROM attack_variants").fetchone()
    assert stored[0] == "multi_turn"
    assert len(json.loads(stored[1])) == 2
    assert "1 to 3" in generator.prompts[0]

    conn2, ledger2, journal2 = p6_env()
    p6_campaign(conn2, "corr-ex", category="TM-EX", attack_count_cap=1)
    loop2, _generator2 = _loop(conn2, ledger2, journal2, [model_json(DISTINCT_TEXTS[3], subcategory="TM-EX-3")])
    loop2.run("corr-ex")
    assert conn2.execute("SELECT mode, turns_json FROM attack_variants").fetchone()[0] == "novel"

    # The default for a TM-PI campaign is also novel and one turn, even though TM-PI has a two-turn seed.
    conn3, ledger3, journal3 = p6_env()
    p6_campaign(conn3, "corr-pi", category="TM-PI", attack_count_cap=1)
    loop3, _generator3 = _loop(conn3, ledger3, journal3, [model_json(DISTINCT_TEXTS[4])])
    loop3.run("corr-pi")
    stored3 = conn3.execute("SELECT mode, turns_json FROM attack_variants").fetchone()
    assert stored3[0] == "novel" and len(json.loads(stored3[1])) == 1


def _two(subcategory: str, canary: str, index: int | None = None) -> str:
    turns = (
        [f"Remember {canary} for the next turn only.", DISTINCT_TEXTS[8]]
        if index is None
        else [DISTINCT_TEXTS[index].replace("CANARY-AF-PI1", canary), DISTINCT_TEXTS[index + 1]]
    )
    body = {
        "turns": turns,
        "subcategory": subcategory,
        "rationale_tag": "two",
    }
    return json.dumps(body)


def _cli(monkeypatch, *argv: str):  # type: ignore[no-untyped-def]
    """Run scripts/orchestrate.py main in process. Its in-memory store is kept so the test can read it."""
    spec = importlib.util.spec_from_file_location("orchestrate_cli", ROOT / "scripts" / "orchestrate.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    shared = sqlite3.connect(":memory:")
    monkeypatch.setattr(module.sqlite3, "connect", lambda *_a, **_k: shared)
    return module.main(list(argv)), shared


def test_the_dry_run_cli_reaches_rank_through_unpinned(monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    code, conn = _cli(monkeypatch, "--dry-run", "--unpinned")
    assert code == 0
    assert '"phase": "done"' in capsys.readouterr().out
    assert conn.execute("SELECT category_pinned, requested_mode FROM campaigns").fetchone() == (0, None)
    # The request placeholder is TM-PI. Rank, not the placeholder, chose where the campaign attacked.
    assert conn.execute("SELECT current_category FROM campaigns").fetchone()[0] == "TM-DS"
    assert {row[0] for row in conn.execute("SELECT category FROM attack_variants")} == {"TM-DS"}
    assert conn.execute("SELECT COUNT(*) FROM coverage_metrics WHERE category = 'TM-PI'").fetchone()[0] == 0


def test_the_dry_run_cli_reaches_multi_turn_through_a_flag(monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    code, conn = _cli(monkeypatch, "--dry-run", "--multi-turn")
    assert code == 0
    capsys.readouterr()
    assert conn.execute("SELECT category_pinned, requested_mode FROM campaigns").fetchone() == (1, "multi_turn")
    rows = conn.execute("SELECT mode, subcategory, turns_json FROM attack_variants").fetchall()
    assert rows and all(row[0] == "multi_turn" and len(json.loads(row[2])) == 2 for row in rows)
    assert {row[1] for row in rows} == {"TM-PI-3"}


def test_the_dry_run_cli_default_stays_pinned_one_turn_novel(monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    code, conn = _cli(monkeypatch, "--dry-run")
    assert code == 0
    capsys.readouterr()
    assert conn.execute("SELECT category_pinned, requested_mode, current_category FROM campaigns").fetchone() == (
        1, None, "TM-PI",
    )
    rows = conn.execute("SELECT mode, turns_json FROM attack_variants").fetchall()
    assert rows and all(row[0] == "novel" and len(json.loads(row[1])) == 1 for row in rows)


@pytest.mark.parametrize("flags", [("--live",), ("--live", "--multi-turn"), ("--live", "--unpinned")])
def test_the_cli_flags_do_not_open_the_live_gate(monkeypatch, capsys, flags) -> None:  # type: ignore[no-untyped-def]
    code, conn = _cli(monkeypatch, *flags)
    assert code == 2
    assert "refused" in capsys.readouterr().out
    assert conn.execute("SELECT name FROM sqlite_master WHERE name = 'campaigns'").fetchone() is None


def test_the_new_flags_refuse_variant_and_resume_combinations(monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    for argv in (("--multi-turn", "--variant-campaign"), ("--unpinned", "--resume", "x")):
        code, _conn = _cli(monkeypatch, *argv)
        assert code == 2
    assert capsys.readouterr().out.count("refused before any call") == 2


# A generator halt reaches the loop as GenerationStopped.halt, which is a StepHalt wrapping the typed Halt.
def _halt_row(conn):  # type: ignore[no-untyped-def]
    return conn.execute("SELECT phase, halt_reason, retryable FROM campaigns WHERE correlation_id = ?", (CID,)).fetchone()


def _logged(conn, code: str) -> int:  # type: ignore[no-untyped-def]
    return conn.execute(
        "SELECT COUNT(*) FROM run_logs WHERE correlation_id = ? AND state = 'halted' AND error_code = ?", (CID, code)
    ).fetchone()[0]


def test_an_ordinary_campaign_records_a_generator_budget_halt_instead_of_crashing() -> None:
    conn, ledger, journal = p6_env()
    p6_campaign(conn, CID, attack_count_cap=2)
    # A model reserve above the budget cap is refused by the ledger, so the generator raises a budget halt.
    loop, _generator = _loop(conn, ledger, journal, [model_json(DISTINCT_TEXTS[0])], reserve_usd=1000.0)
    outcome = loop.run(CID)
    assert (outcome.phase, outcome.error_code, outcome.sequences) == ("halted", "budget_exceeded", 0)
    assert "BudgetExceeded" in outcome.detail
    assert _halt_row(conn) == ("halted", "budget_exceeded", 0)
    assert _logged(conn, "budget_exceeded") == 1
    with pytest.raises(CampaignOpen):  # a budget halt is not retryable, so it cannot be resumed
        loop.resume(CID)


def test_a_variant_campaign_records_a_generator_budget_halt_instead_of_crashing() -> None:
    conn, ledger, journal = p6_env(max_attacks=80)
    p6_campaign(conn, CID, attack_count_cap=3)
    _partial(conn, "variant-parent")
    loop, _generator = _loop(conn, ledger, journal, [model_json(DISTINCT_TEXTS[0])], reserve_usd=1000.0)
    outcome = loop.run(CID, variants=3)
    assert (outcome.phase, outcome.error_code, outcome.sequences) == ("halted", "budget_exceeded", 0)
    assert _halt_row(conn) == ("halted", "budget_exceeded", 0)
    assert _logged(conn, "budget_exceeded") == 1
    assert conn.execute("SELECT COUNT(*) FROM mutation_claims").fetchone()[0] == 0
    with pytest.raises(CampaignOpen):
        loop.resume(CID)


def _stop_generation(generator, halt_value: Halt) -> None:  # type: ignore[no-untyped-def]
    """Make the generator stop the way run_step does: GenerationStopped carrying the StepHalt."""
    real = generator.generate
    state = {"stop": True}

    def generate(*args, **kwargs):  # type: ignore[no-untyped-def]
        if state["stop"]:
            raise GenerationStopped("halt", halt_value.detail, StepHalt(halt_value))
        return real(*args, **kwargs)

    generator.generate = generate
    generator.release = lambda: state.update(stop=False)


def test_a_retryable_generator_halt_is_recorded_and_the_campaign_resumes() -> None:
    conn, ledger, journal = p6_env()
    p6_campaign(conn, CID, attack_count_cap=1)
    loop, generator = _loop(conn, ledger, journal, [model_json(DISTINCT_TEXTS[0])])
    _stop_generation(generator, Halt("target_unreachable", True, "rate_limited step attempt bound reached"))
    outcome = loop.run(CID)
    assert (outcome.phase, outcome.error_code) == ("halted", "target_unreachable")
    assert outcome.detail == "rate_limited step attempt bound reached"
    assert _halt_row(conn) == ("halted", "target_unreachable", 1)
    assert _logged(conn, "target_unreachable") == 1
    generator.release()
    resumed = loop.resume(CID)
    assert resumed.phase == "done" and resumed.sequences == 1
    assert _halt_row(conn) == ("done", None, 0)


def test_a_retryable_generator_halt_in_a_variant_campaign_is_recorded_as_retryable() -> None:
    conn, ledger, journal = p6_env(max_attacks=80)
    p6_campaign(conn, CID, attack_count_cap=3)
    _partial(conn, "variant-parent")
    loop, generator = _loop(conn, ledger, journal, [model_json(DISTINCT_TEXTS[0])])
    _stop_generation(generator, Halt("target_unreachable", True, "rate_limited campaign attempt bound reached"))
    outcome = loop.run(CID, variants=3)
    assert (outcome.phase, outcome.error_code) == ("halted", "target_unreachable")
    assert _halt_row(conn) == ("halted", "target_unreachable", 1)
    assert _logged(conn, "target_unreachable") == 1
