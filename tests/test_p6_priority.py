"""P6 prioritization from persisted evidence. Rows are seeded in SQLite, nothing comes from agent claims."""

from __future__ import annotations

import sqlite3

import pytest

from agentforge.orchestrator import priority
from agentforge.orchestrator.policy import ConfigError, Weights, load_config, parse_config, validate_variants
from agentforge.orchestrator.priority import Evidence, load_evidence, next_category, rank
from agentforge.store.records import insert_exploit
from tests.fixtures import p6_campaign, p6_store

W = Weights()
ORDER = ("TM-PI", "TM-EX", "TM-DS", "TM-SC", "TM-TM", "TM-ID")
SEEDED = frozenset({"TM-PI", "TM-EX", "TM-DS"})
VERSION = "9f03654"


def _coverage(conn: sqlite3.Connection, category: str, cases: int, passes: int, fails: int = 0) -> None:
    conn.execute(
        "INSERT INTO coverage_metrics (category, system_version, case_count, pass_count, fail_count) VALUES (?, ?, ?, ?, ?)",
        (category, VERSION, cases, passes, fails),
    )


def _exploit(conn: sqlite3.Connection, category: str, severity: str = "high", status: str = "draft") -> str:
    exploit_id = f"exp-{category}-{severity}-{status}"
    insert_exploit(
        conn,
        {
            "id": exploit_id, "severity": severity, "category": category, "reproduction_steps": exploit_id,
            "observed_behavior": "o", "expected_behavior": "e", "system_version": VERSION, "status": status,
        },
    )
    return exploit_id


def _handoff(conn: sqlite3.Connection) -> None:
    conn.execute(
        "INSERT INTO version_handoffs (target_pin, previous_pin, detected_at, status, correlation_id) VALUES ('a1b2c3d', ?, 'now', 'pending', 'c')",
        (VERSION,),
    )


def _covered(conn: sqlite3.Connection) -> None:
    for category in SEEDED:
        _coverage(conn, category, 4, 4)


def _rank(conn: sqlite3.Connection) -> priority.Ranking:
    return next_category(conn, VERSION, SEEDED, W, ORDER)


def test_open_high_finding_outranks_a_gap_and_gap_outranks_covered() -> None:
    conn = p6_store()
    _coverage(conn, "TM-PI", 4, 4)
    _coverage(conn, "TM-DS", 4, 4)
    _exploit(conn, "TM-DS")
    result = _rank(conn)
    assert [s.category for s in result.ordered] == ["TM-DS", "TM-EX", "TM-PI"]
    assert result.ordered[0].components == {"open_high_finding": 100}
    assert result.ordered[1].components == {"coverage_gap": 40}
    assert not result.fallback


def test_zero_case_count_is_a_gap_and_low_pass_rate_scores() -> None:
    conn = p6_store()
    _coverage(conn, "TM-PI", 0, 0)
    _coverage(conn, "TM-EX", 10, 2, 8)
    _coverage(conn, "TM-DS", 10, 10)
    by = {s.category: s for s in _rank(conn).ordered}
    assert by["TM-PI"].components == {"coverage_gap": 40}
    assert by["TM-EX"].components == {"low_pass_rate": 20}
    assert by["TM-DS"].total == 0


def test_ties_are_stable_by_category_name() -> None:
    conn = p6_store()
    first = [s.category for s in _rank(conn).ordered]
    assert first == ["TM-DS", "TM-EX", "TM-PI"]
    assert [s.category for s in _rank(conn).ordered] == first


def test_ranking_follows_persisted_rows_not_memory() -> None:
    conn = p6_store()
    _covered(conn)
    assert _rank(conn).fallback
    exploit_id = _exploit(conn, "TM-EX")
    assert _rank(conn).first == "TM-EX"
    conn.execute("DELETE FROM exploits WHERE id = ?", (exploit_id,))
    assert _rank(conn).fallback
    assert rank(Evidence(), SEEDED, W, ORDER).first == "TM-DS"


def test_rejected_and_medium_findings_do_not_count_as_open_high() -> None:
    conn = p6_store()
    _covered(conn)
    _exploit(conn, "TM-PI", "high", "rejected")
    _exploit(conn, "TM-EX", "medium", "draft")
    assert _rank(conn).fallback


def test_regression_component_needs_category_evidence_and_a_pending_handoff() -> None:
    conn = p6_store()
    _covered(conn)
    _handoff(conn)
    assert all(s.total == 0 for s in _rank(conn).ordered)  # a handoff alone raises nothing
    _exploit(conn, "TM-PI", "low", "draft")
    result = _rank(conn)
    assert {s.category: s.total for s in result.ordered} == {"TM-PI": 60, "TM-EX": 0, "TM-DS": 0}
    assert result.first == "TM-PI"


def test_regression_evidence_without_a_handoff_scores_nothing() -> None:
    conn = p6_store()
    _covered(conn)
    _exploit(conn, "TM-PI", "low", "draft")
    assert all(s.total == 0 for s in _rank(conn).ordered)


def test_regression_cases_row_is_category_evidence() -> None:
    conn = p6_store()
    _covered(conn)
    parent = _exploit(conn, "TM-DS", "low", "rejected")  # rejected, so it is not evidence by itself
    conn.execute(
        "INSERT INTO regression_cases (id, exploit_id, category, expected_safe_behavior, system_version) VALUES ('rc-1', ?, 'TM-DS', 'safe', ?)",
        (parent, VERSION),
    )
    _handoff(conn)
    assert {s.category: s.total for s in _rank(conn).ordered} == {"TM-DS": 60, "TM-EX": 0, "TM-PI": 0}


def _ran(conn: sqlite3.Connection, correlation_id: str, category: str, when: str) -> None:
    conn.execute("UPDATE campaigns SET phase = 'done'")
    p6_campaign(conn, correlation_id, category=category)
    conn.execute("UPDATE campaigns SET updated_at = ? WHERE correlation_id = ?", (when, correlation_id))
    conn.execute("UPDATE campaigns SET phase = 'done'")


def test_all_zero_rotates_to_the_least_recently_run_category() -> None:
    conn = p6_store()
    _covered(conn)
    result = _rank(conn)
    assert result.fallback and result.first == "TM-PI"  # never run: fixed order
    _ran(conn, "c-1", "TM-PI", "2026-10-19T10:00:00Z")
    assert _rank(conn).first == "TM-EX"
    _ran(conn, "c-2", "TM-EX", "2026-10-19T11:00:00Z")
    assert _rank(conn).first == "TM-DS"
    _ran(conn, "c-3", "TM-DS", "2026-10-19T12:00:00Z")
    assert _rank(conn).first == "TM-PI"  # the oldest run


def test_nothing_attackable_returns_none_and_unseeded_are_skipped_with_a_reason() -> None:
    conn = p6_store()
    none = next_category(conn, VERSION, frozenset(), W, ORDER)
    assert none.first is None and none.fallback
    some = _rank(conn)
    assert some.skipped["TM-SC"] == "no seed for this category"
    assert set(some.skipped) == {"TM-SC", "TM-TM", "TM-ID"}
    assert some.as_audit()["skipped"] == some.skipped


def test_excluded_categories_are_not_offered_again() -> None:
    conn = p6_store()
    result = next_category(conn, VERSION, SEEDED, W, ORDER, exclude=frozenset({"TM-DS"}))
    assert "TM-DS" not in [s.category for s in result.ordered]


def test_load_evidence_is_read_only() -> None:
    conn = p6_store()
    before = conn.total_changes
    evidence = load_evidence(conn, VERSION)
    assert conn.total_changes == before and not conn.in_transaction
    assert evidence.coverage == {} and not evidence.pending_handoff


def test_committed_config_loads_and_enforces_ceilings() -> None:
    config = load_config()
    assert config.variants.variants_requested == 10 and config.limits.max_turns == 3
    assert config.max_turns_total == 30
    for value in (0, 11, -1, 2.5, "3", True, None):
        with pytest.raises(ConfigError):
            validate_variants(value)
    assert validate_variants(1) == 1 and validate_variants(10) == 10


def _raw() -> dict[str, object]:
    return {
        "weights": {"open_high_finding": 1, "regression_component": 1, "coverage_gap": 1, "low_pass_rate": 1, "low_pass_rate_below": 0.5},
        "fallback_order": ["TM-PI"],
        "retry": {"max_attempts_per_step": 3, "max_attempts_per_campaign": 6, "base_delay_s": 1, "max_delay_s": 30},
        "stop": {"after_attacks": 5, "spend_fraction": 0.25, "max_redirects": 1},
        "limits": {"max_sequences_per_campaign": 10, "max_turns": 3, "max_rejections": 2, "max_mutations_per_parent": 2, "max_mutation_depth": 2},
        "novelty": {"threshold": 0.35},
        "variant_campaign": {"variants_requested": 10, "max_total_rejections": 10, "max_turns_per_variant": 1},
    }


def test_config_refuses_values_above_a_hard_ceiling() -> None:
    assert parse_config(_raw()).limits.max_turns == 3
    raw = _raw()
    raw["limits"] = {**_raw()["limits"], "max_turns": 5}  # type: ignore[dict-item]
    with pytest.raises(ConfigError, match="max_turns"):
        parse_config(raw)
    raw = _raw()
    raw["variant_campaign"] = {**_raw()["variant_campaign"], "variants_requested": 11}  # type: ignore[dict-item]
    with pytest.raises(ConfigError, match="variants_requested"):
        parse_config(raw)
    raw = _raw()
    raw["variant_campaign"] = {**_raw()["variant_campaign"], "max_turns_per_variant": 4}  # type: ignore[dict-item]
    with pytest.raises(ConfigError, match="max_turns_per_variant"):
        parse_config(raw)
    with pytest.raises(ConfigError):
        parse_config({})
    with pytest.raises(ConfigError):
        parse_config([])
