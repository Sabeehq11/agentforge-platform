from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from agentforge.gates.provider_cap import local_caps_problem
from agentforge.safety.operator_approval import (
    OperatorApprovalRefused,
    authorize_spend,
    load_approvals,
    require_operator_approval,
    require_public_target,
)
from agentforge.safety.spend_limits import SpendLimitNotAttested

ROOT = Path(__file__).resolve().parents[1]
TODAY = date(2026, 10, 19)


def _write(path: Path, body: str) -> Path:
    target = path / "approval.yaml"
    target.write_text(body, encoding="utf-8")
    return target


def test_committed_example_is_empty() -> None:
    assert load_approvals(ROOT / "config" / "operator_approval.example.yaml") == []
    assert "attestations: []" in (ROOT / "config" / "spend_limits.yaml").read_text(encoding="utf-8")


def test_missing_file_refuses(tmp_path: Path) -> None:
    with pytest.raises(OperatorApprovalRefused):
        require_operator_approval("local-target", load_approvals(tmp_path / "missing.yaml"), today=TODAY)


@pytest.mark.parametrize(
    "body",
    [
        "approvals: []\n",
        "approvals:\n  - {approved_by: op, approved_on: 2026-10-19, scope: local-target, max_usd: 6.0, purpose: local-p4}\n",
        "approvals:\n  - {approved_by: op, approved_on: 2026-10-19, scope: other, max_usd: 5.0, purpose: local-p4}\n",
        "approvals:\n  - {approved_by: op, approved_on: 2026-10-01, scope: local-target, max_usd: 5.0, purpose: local-p4}\n",
        "approvals:\n  - {approved_by: '', approved_on: 2026-10-19, scope: local-target, max_usd: 5.0, purpose: local-p4}\n",
    ],
)
def test_bad_approval_refuses(tmp_path: Path, body: str) -> None:
    with pytest.raises(OperatorApprovalRefused):
        require_operator_approval("local-target", load_approvals(_write(tmp_path, body)), today=TODAY)


def test_fresh_five_dollar_approval_matches_only_its_scope(tmp_path: Path) -> None:
    body = (
        "approvals:\n"
        "  - {approved_by: op, approved_on: 2026-10-19, scope: local-target, max_usd: 5.0, purpose: local-p4}\n"
    )
    approvals = load_approvals(_write(tmp_path, body))
    assert require_operator_approval("local-target", approvals, today=TODAY).scope == "local-target"
    with pytest.raises(OperatorApprovalRefused):
        require_operator_approval("openrouter", approvals, today=TODAY)


def test_public_target_approval_is_origin_bound_and_not_a_spend_ceiling(tmp_path: Path) -> None:
    origin = "https://target.example"
    fresh = (
        "approvals:\n"
        "  - {approved_by: op, approved_on: 2026-10-19, scope: public-target, max_usd: 0, purpose: one window,"
        " origin: https://target.example/}\n"
    )
    approvals = load_approvals(_write(tmp_path, fresh))
    assert require_public_target(approvals, origin=origin, today=TODAY).origin == origin
    assert require_public_target(approvals, origin=origin + ":443", today=TODAY).origin == origin
    with pytest.raises(OperatorApprovalRefused):
        require_public_target(approvals, origin="https://other.example", today=TODAY)
    with pytest.raises(OperatorApprovalRefused):
        require_public_target(approvals, origin=origin, today=date(2026, 10, 21))
    with pytest.raises(SpendLimitNotAttested):
        authorize_spend("openrouter", attestations=[], approvals=approvals, today=TODAY)

    stale = (
        "approvals:\n"
        "  - {approved_by: op, approved_on: 2026-10-17, scope: public-target, max_usd: 0, purpose: one window,"
        " origin: https://target.example}\n"
    )
    priced = (
        "approvals:\n"
        "  - {approved_by: op, approved_on: 2026-10-19, scope: public-target, max_usd: 5.0, purpose: one window,"
        " origin: https://target.example}\n"
    )
    unbound = (
        "approvals:\n"
        "  - {approved_by: op, approved_on: 2026-10-19, scope: public-target, max_usd: 0, purpose: one window}\n"
    )
    for body in (stale, priced, unbound):
        with pytest.raises(OperatorApprovalRefused):
            require_public_target(load_approvals(_write(tmp_path, body)), origin=origin, today=TODAY)


def test_approval_does_not_write_an_attestation(tmp_path: Path) -> None:

    body = (
        "approvals:\n"
        "  - {approved_by: op, approved_on: 2026-10-19, scope: openrouter, max_usd: 5.0, purpose: probe}\n"
    )
    approvals = load_approvals(_write(tmp_path, body))
    assert authorize_spend("openrouter", attestations=[], approvals=approvals, today=TODAY) == "operator_approval"
    from agentforge.safety.operator_approval import OperatorApprovalRefused

    with pytest.raises(OperatorApprovalRefused):
        require_operator_approval("local-target", approvals, today=TODAY)
    with pytest.raises(SpendLimitNotAttested):
        authorize_spend("target", attestations=[], approvals=approvals, today=TODAY)
    assert not (tmp_path / "spend_limits.yaml").exists()


def _local_cap_root(tmp_path: Path) -> Path:
    root = tmp_path / "caps"
    (root / "Docs/attestations").mkdir(parents=True)
    (root / "config").mkdir()
    (root / "src/agentforge/safety").mkdir(parents=True)
    (root / "Docs/attestations/provider-cap-deviation.yaml").write_text(
        "scope: in-repo-caps-only\napproved_by: Test Human\napproved_on: 2026-10-22\nstatement: local caps only\n",
        encoding="utf-8",
    )
    (root / "config/budget.yaml").write_text(
        "per_run_usd: 5\nper_day_usd: 5\nhard_ceiling_per_run_usd: 5\nhard_ceiling_per_day_usd: 15\n",
        encoding="utf-8",
    )
    (root / "src/agentforge/safety/ledger.py").write_text(
        "SHARED_CEILING_USD = 5.0\nif committed_usd(conn) > SHARED_CEILING_USD: raise BudgetExceeded\n",
        encoding="utf-8",
    )
    (root / "src/agentforge/safety/budget.py").write_text(
        "class BudgetExceeded(Exception):\n    pass\n\ndef reserve(self):\n    raise BudgetExceeded()\n",
        encoding="utf-8",
    )
    (root / "src/agentforge/safety/chokepoint.py").write_text(
        "LIVE_ENABLED = False\nPROVIDER_ENABLED = False\n", encoding="utf-8"
    )
    (root / "Docs/attestations/spend-reconciliation.yaml").write_text(
        "as_of: 2026-10-22\nincurred_usd: 0.30\nopen_reserved_usd: 0\nuncertain_usd: 0\nexcess_usd: 0\n",
        encoding="utf-8",
    )
    (root / "config/spend_limits.yaml").write_text("attestations: []\n", encoding="utf-8")
    return root


def test_verified_local_caps_replace_a_missing_provider_attestation(tmp_path: Path) -> None:
    root = _local_cap_root(tmp_path)
    today = date(2026, 10, 22)
    assert local_caps_problem(root, today=today) is None
    assert authorize_spend("openrouter", attestations=[], approvals=[], today=today, root=root) == "in_repo_caps"
    assert authorize_spend("target", attestations=[], approvals=[], today=today, root=root) == "in_repo_caps"
    assert (root / "config/spend_limits.yaml").read_text(encoding="utf-8") == "attestations: []\n"


def test_missing_local_caps_still_fail_closed(tmp_path: Path) -> None:
    root = _local_cap_root(tmp_path)
    today = date(2026, 10, 22)
    (root / "config/budget.yaml").write_text(
        "per_run_usd: 50\nper_day_usd: 5\nhard_ceiling_per_run_usd: 50\nhard_ceiling_per_day_usd: 15\n",
        encoding="utf-8",
    )
    with pytest.raises(SpendLimitNotAttested, match="local caps are not enforced"):
        authorize_spend("openrouter", attestations=[], approvals=[], today=today, root=root)
    (root / "src/agentforge/safety/ledger.py").write_text("SHARED_CEILING_USD = 50\n", encoding="utf-8")
    (root / "config/budget.yaml").write_text(
        "per_run_usd: 5\nper_day_usd: 5\nhard_ceiling_per_run_usd: 5\nhard_ceiling_per_day_usd: 15\n",
        encoding="utf-8",
    )
    with pytest.raises(SpendLimitNotAttested, match="shared \\$5 ledger ceiling"):
        authorize_spend("target", attestations=[], approvals=[], today=today, root=root)
    with pytest.raises(SpendLimitNotAttested, match="no operator-approval scope"):
        authorize_spend("other", attestations=[], approvals=[], today=today, root=root)
