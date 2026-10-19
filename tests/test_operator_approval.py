from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from agentforge.safety.operator_approval import (
    OperatorApprovalRefused,
    load_approvals,
    require_operator_approval,
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


def test_approval_does_not_write_an_attestation(tmp_path: Path) -> None:
    from agentforge.safety.operator_approval import authorize_spend

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
