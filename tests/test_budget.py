from __future__ import annotations

from pathlib import Path

import pytest

from agentforge.safety.budget import (
    Budget,
    BudgetExceeded,
    Caps,
    KillSwitchEngaged,
    NotApproved,
    approval_token,
    load_caps,
)

ROOT = Path(__file__).resolve().parents[1]
SECRET = "test-secret-not-a-real-credential"


def caps(**kw: float) -> Caps:
    base = dict(
        per_run_usd=1.0,
        per_day_usd=2.0,
        max_attacks_per_run=3,
        hard_ceiling_per_run_usd=5.0,
        hard_ceiling_per_day_usd=10.0,
    )
    base.update(kw)
    return Caps(
        per_run_usd=base["per_run_usd"],
        per_day_usd=base["per_day_usd"],
        max_attacks_per_run=int(base["max_attacks_per_run"]),
        hard_ceiling_per_run_usd=base["hard_ceiling_per_run_usd"],
        hard_ceiling_per_day_usd=base["hard_ceiling_per_day_usd"],
    )


def approved(c: Caps | None = None) -> Budget:
    c = c or caps()
    b = Budget(c)
    b.approve(approval_token(c, SECRET), SECRET)
    return b


def test_shipped_config_loads() -> None:
    c = load_caps(ROOT / "config" / "budget.yaml")
    assert c.per_run_usd <= c.hard_ceiling_per_run_usd


def test_cap_above_ceiling_rejected(tmp_path: Path) -> None:
    f = tmp_path / "b.yaml"
    f.write_text(
        "per_run_usd: 9\nper_day_usd: 1\nmax_attacks_per_run: 1\nhard_ceiling_per_run_usd: 5\nhard_ceiling_per_day_usd: 5\n"
    )
    with pytest.raises(ValueError):
        load_caps(f)


def test_unapproved_budget_reserves_nothing() -> None:
    b = Budget(caps())
    with pytest.raises(NotApproved):
        b.reserve(0.01)
    assert b.run_spent == 0


def test_token_for_other_numbers_rejected() -> None:
    other = approval_token(caps(per_run_usd=4.0), SECRET)
    with pytest.raises(NotApproved):
        Budget(caps()).approve(other, SECRET)


def test_wrong_secret_or_empty_rejected() -> None:
    token = approval_token(caps(), SECRET)
    with pytest.raises(NotApproved):
        Budget(caps()).approve(token, "different-secret")
    with pytest.raises(NotApproved):
        Budget(caps()).approve(token, "")


def test_per_run_cap_raises_before_overspend() -> None:
    b = approved()
    b.reserve(0.6)
    with pytest.raises(BudgetExceeded):
        b.reserve(0.5)
    assert b.run_spent == pytest.approx(0.6)


def test_per_day_cap_spans_runs() -> None:
    b = approved(caps(per_run_usd=1.5, per_day_usd=2.0))
    b.reserve(1.2)
    b.start_run()
    with pytest.raises(BudgetExceeded):
        b.reserve(1.0)
    assert b.day_spent == pytest.approx(1.2)


def test_attack_count_cap() -> None:
    b = approved(caps(max_attacks_per_run=2))
    b.reserve(0.01)
    b.reserve(0.01)
    with pytest.raises(BudgetExceeded):
        b.reserve(0.01)
    assert b.attacks == 2


def test_kill_switch_blocks_next_reserve() -> None:
    b = approved()
    b.reserve(0.01)
    b.kill()
    with pytest.raises(KillSwitchEngaged):
        b.reserve(0.0)
    assert b.killed


def test_negative_amount_rejected() -> None:
    with pytest.raises(ValueError):
        approved().reserve(-1.0)
