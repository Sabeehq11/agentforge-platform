from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

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
