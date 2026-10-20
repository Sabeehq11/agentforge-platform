"""Ten-variant campaign. Scripted model, fake transport, in-memory ledger. No network and no spend."""

from __future__ import annotations

import json
import sqlite3

import pytest
from fixtures import DISTINCT_TEXTS, FakeTarget, ScriptedModel, answer, model_json, p6_campaign, p6_client, p6_env
from agentforge.agents.judge import RulesJudge, StubJudgeModel
from agentforge.agents.red_team_generator import RedTeamGenerator, load_parent
from agentforge.evals.cases import load_cases
from agentforge.evals.login import LoginRequest
from agentforge.orchestrator.loop import CampaignLoop
from agentforge.orchestrator.policy import ConfigError, load_config, validate_variants
from agentforge.orchestrator.sequence import SequenceRunner

CID = "corr-p6"
PARENT_TURN = DISTINCT_TEXTS[5]


def _parent(conn: sqlite3.Connection, verdict: str = "partial", *, by: str = "executor", cid: str = CID) -> int:
    transcript = {
        "transcript_id": "rec-parent",
        "correlation_id": cid,
        "schema_version": "v1",
        "recorded_by": by,
        "turns": [
            {"role": "user", "content": PARENT_TURN},
            {"role": "target", "content": "The request is unclear."},
        ],
    }
    cursor = conn.execute(
        """
        INSERT INTO signals (correlation_id, category, subcategory, verdict, evidence_hash, dedup_key, transcript_id,
            transcript_json, parent_id, depth, recorded_at)
        VALUES (?, 'TM-PI', 'TM-PI-1', ?, ?, ?, 'rec-parent', ?, NULL, 0, '2026-10-19T00:00:00Z')
        """,
        (cid, verdict, "b" * 64, f"k-{verdict}-{cid}-{by}", json.dumps(transcript)),
    )
    conn.commit()
    return int(cursor.lastrowid or 0)


def _loop(conn, ledger, journal, replies, *, max_requests: int = 200):  # type: ignore[no-untyped-def]
    config = load_config()
    seeds = load_cases()
    generator = RedTeamGenerator(
        conn, journal, config, ScriptedModel(replies), seeds,
        alloc_step=iter(range(1, 400)).__next__, sleep=lambda _s: None, reserve_usd=0.0,
    )
    target = FakeTarget([answer("I will not follow that instruction.")])
    runner = SequenceRunner(
        conn, journal, config, p6_client(target, ledger, ledger._budget, max_requests=max_requests),
        LoginRequest("copilot_doc_a", "not-committed"), "100", sleep=lambda _s: None,
        request_cap=config.limits.max_sequences_per_campaign,
    )
    judge = RulesJudge(
        "config/models.yaml", ledger, stub=StubJudgeModel(), canaries={"TM-PI-1": "CANARY-AF-PI1"}, fixture_only=True
    )
    loop = CampaignLoop(conn, journal, config, generator, runner, judge, seeds, observed_pin="9f03654")
    return loop, target, generator


def _pool() -> list[str]:
    """Every distinct text except the parent turn, which would score as a duplicate of itself."""
    return [text for text in DISTINCT_TEXTS if text != PARENT_TURN]


def _replies(n: int) -> list[str]:
    pool = _pool()
    return [model_json(pool[i], tag=f"v{i}") for i in range(n)]


def test_ten_distinct_variants_from_one_persisted_partial_parent() -> None:
    conn, ledger, journal = p6_env(max_attacks=80)
    p6_campaign(conn, CID, attack_count_cap=10)
    parent_id = _parent(conn)
    assert load_parent(conn, parent_id, load_config()).turns == (PARENT_TURN,)
    loop, target, _generator = _loop(conn, ledger, journal, _replies(10))
    outcome = loop.run(CID, variants=10)
    assert outcome.phase == "done" and outcome.detail == "10 variants"
    assert outcome.sequences == 10
    stored = conn.execute("SELECT correlation_id, turns_json FROM attack_variants").fetchall()
    report = outcome.novelty or {}
    printed = report["pairs"]
    parent_pairs = [row for row in printed if str(row["b"]).startswith("parent:")]
    variant_pairs = [row for row in printed if not str(row["b"]).startswith("parent:")]
    assert report["pair_count"] == 55 and len(printed) == 55
    assert len(parent_pairs) == 10 and len(variant_pairs) == 45
    assert round(float(report["minimum_distance"]), 4) == min(row["distance"] for row in printed)
    assert float(report["minimum_distance"]) >= load_config().novelty_threshold
    targets = [row for row in journal.rows(CID) if row.role == "executor" and row.kind == "target" and row.state == "completed"]
    assert len(targets) == 20  # setup plus one turn, ten times
    verdicts = [row for row in conn.execute("SELECT agent_role FROM run_logs WHERE agent_role = 'judge'")]
    assert len(verdicts) == 10
    assert len(stored) == 10 and {row[0] for row in stored} == {CID}
    assert len({row[1] for row in stored}) == 10
    assert target.chat_calls == 10
    assert ledger.totals("judge").incurred_usd == 0


def test_a_requested_count_outside_one_to_ten_refuses_before_any_call() -> None:
    for bad in (0, 11, -1, 1.5, "10"):
        with pytest.raises(ConfigError):
            validate_variants(bad)
    conn, ledger, journal = p6_env()
    p6_campaign(conn, CID, attack_count_cap=10)
    _parent(conn)
    loop, target, generator = _loop(conn, ledger, journal, _replies(1))
    with pytest.raises(ConfigError):
        loop.run(CID, variants=11)
    assert target.calls == [] and generator.prompts == []


def test_no_eligible_parent_sends_nothing() -> None:
    conn, ledger, journal = p6_env()
    p6_campaign(conn, CID, attack_count_cap=10)
    loop, target, generator = _loop(conn, ledger, journal, _replies(1))
    missing = loop.run(CID, variants=3)
    assert missing.phase == "halted" and missing.detail == "no eligible parent"
    assert target.calls == []
    for verdict, by in (("fail", "executor"), ("pass", "executor"), ("partial", "red_team")):
        if verdict == "pass":
            continue
        _parent(conn, verdict, by=by)
    refused = loop.run(CID, variants=3)
    assert refused.detail == "no eligible parent" and generator.prompts == [] and target.calls == []


def test_near_duplicates_stop_early_without_an_error() -> None:
    conn, ledger, journal = p6_env(max_attacks=80)
    p6_campaign(conn, CID, attack_count_cap=10)
    _parent(conn)
    replies = _replies(6) + [model_json(_pool()[0], tag="dup")] * 12
    loop, _target, _generator = _loop(conn, ledger, journal, replies)
    outcome = loop.run(CID, variants=10)
    assert outcome.phase == "done" and outcome.detail == "6 variants"
    assert outcome.sequences == 6
