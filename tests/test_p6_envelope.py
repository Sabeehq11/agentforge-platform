"""The v1 envelope is unchanged, and the gates still refuse with both switches off."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from agentforge.safety.chokepoint import LIVE_ENABLED, PROVIDER_ENABLED, RefusedByChokepoint, request
from agentforge.safety.allowlist import Allowlist, Entry
from agentforge.safety.budget import Budget, Caps, approval_token
from agentforge.safety.operator_approval import OperatorApproval
from agentforge.safety.rate import RateCap
from agentforge.safety.spend_limits import Attestation
from datetime import date

ROOT = Path(__file__).resolve().parents[1]


def test_schema_diff_reports_no_breaking_change() -> None:
    result = subprocess.run([sys.executable, "scripts/check_schema_diff.py"], cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_both_switches_off_still_refuses_before_the_transport() -> None:
    assert LIVE_ENABLED is False and PROVIDER_ENABLED is False
    calls: list[str] = []

    def transport(method: str, url: str, headers: object = None, body: object = None) -> object:
        calls.append(url)
        raise AssertionError("transport was called")

    caps = Caps(1.0, 1.0, 1, 5.0, 5.0)
    budget = Budget(caps)
    budget.approve(approval_token(caps, "secret"), "secret")
    try:
        request(
            "GET", "https://target.example/interface/login/login.php", transport=transport,
            allowlist=Allowlist((Entry("https", "target.example", 443, "/"),)), budget=budget,
            attestations=[Attestation("target", "k", 1.0, "someone", date(2026, 10, 17))], provider="target",
            est_cost_usd=0.0, today=date(2026, 10, 20), rate_cap=RateCap(2),
            approvals=[OperatorApproval("op", date(2026, 10, 20), "public-target", 0.0, "fixture", "https://target.example")],
        )
    except RefusedByChokepoint as exc:
        assert exc.gate == "live"
    assert calls == []
