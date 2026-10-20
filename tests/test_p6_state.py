"""P6 campaign state and migration 0003. Scripted, no network."""

from __future__ import annotations

import pytest

from agentforge.contracts.validate import ContractError
from agentforge.orchestrator import state
from tests.fixtures import campaign_request, p6_campaign, p6_store

CID = "corr-p6"


def test_migration_0003_adds_only_the_six_tables() -> None:
    conn = p6_store()
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert {"campaigns", "dispatch_journal", "signals", "version_baselines", "version_handoffs", "attack_variants"} <= names
    versions = [r[0] for r in conn.execute("SELECT version FROM schema_migrations ORDER BY version")]
    assert versions == ["0001", "0002", "0003"]
    sql = conn.execute("SELECT sql FROM sqlite_master WHERE name = 'run_logs'").fetchone()[0]
    assert "'harness'" in sql and "executor" not in sql  # run_logs CHECKs are untouched


def test_phase_change_and_run_log_commit_together() -> None:
    conn = p6_store()
    p6_campaign(conn)
    state.set_phase(conn, CID, "attacking", role="red_team")
    assert state.require_campaign(conn, CID)["phase"] == "attacking"
    rows = conn.execute("SELECT agent_role, state FROM run_logs WHERE correlation_id = ? ORDER BY id", (CID,)).fetchall()
    assert [tuple(r) for r in rows] == [("orchestrator", "queued"), ("red_team", "running")]


def test_a_failed_run_log_rolls_back_the_phase() -> None:
    conn = p6_store()
    p6_campaign(conn)
    with pytest.raises(ValueError):
        state.set_phase(conn, CID, "attacking", role="executor")  # not a run_logs role
    assert state.require_campaign(conn, CID)["phase"] == "selecting"


def test_halt_is_typed_and_only_retryable_resumes() -> None:
    conn = p6_store()
    p6_campaign(conn)
    state.halt(conn, CID, "target_unreachable", "unknown_outcome", retryable=True)
    row = state.require_campaign(conn, CID)
    assert (row["phase"], row["halt_reason"], row["retryable"]) == ("halted", "target_unreachable", 1)
    assert state.resume_campaign(conn, CID)["phase"] == "selecting"
    state.halt(conn, CID, "no_findings_in_window", "none", retryable=False)
    with pytest.raises(state.CampaignOpen):
        state.resume_campaign(conn, CID)
    with pytest.raises(ValueError):
        state.halt(conn, CID, "new_code", "x", retryable=False)


def test_second_open_campaign_and_reused_id_are_refused() -> None:
    conn = p6_store()
    p6_campaign(conn)
    other = {**campaign_request(), "correlation_id": "corr-other"}
    with pytest.raises(state.CampaignOpen):
        state.open_campaign(conn, other, system_version="9f03654")  # type: ignore[arg-type]
    state.halt(conn, CID, "no_findings_in_window", "x", retryable=False)
    with pytest.raises(ContractError):
        state.open_campaign(conn, {**campaign_request(), "correlation_id": CID}, system_version="9f03654")  # type: ignore[arg-type]
    state.open_campaign(conn, other, system_version="9f03654")  # type: ignore[arg-type]


def test_counters_are_a_closed_set() -> None:
    conn = p6_store()
    p6_campaign(conn)
    state.bump(conn, CID, "sequences_started")
    state.bump(conn, CID, "turns_sent", 3)
    row = state.require_campaign(conn, CID)
    assert (row["sequences_started"], row["turns_sent"]) == (1, 3)
    with pytest.raises(ValueError):
        state.bump(conn, CID, "spent_usd")
