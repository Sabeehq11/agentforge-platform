from __future__ import annotations

import sqlite3
from datetime import date

import pytest

from agentforge.safety.allowlist import Allowlist, Entry
from agentforge.safety.budget import BudgetExceeded, Caps, approval_token
from agentforge.safety.chokepoint import RefusedByChokepoint, Response, request
from agentforge.safety.ledger import Ledger, load_shared_budget
from agentforge.safety.operator_approval import OperatorApproval
from agentforge.store.migrate import migrate

SECRET = "test-secret"
TODAY = date(2026, 10, 19)
CAPS = Caps(5, 5, 20, 5, 15)
URL = "https://target.example/interface/login/login.php"


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    migrate(conn)
    return conn


def test_new_budget_refuses_before_transport_when_prior_spend_would_exceed_five() -> None:
    conn = _conn()
    conn.execute("INSERT INTO agent_spend VALUES ('prior', 'target', 0, 4.90, 'incurred')")
    budget = load_shared_budget(conn, CAPS, approval_token(CAPS, SECRET), SECRET)
    calls: list[str] = []

    def transport(method: str, url: str, headers: dict[str, str] | None = None, body: bytes | str | None = None) -> Response:
        calls.append(url)
        return Response(200, b"should-not-run")

    with pytest.raises(RefusedByChokepoint) as caught:
        request(
            "POST",
            URL,
            transport=transport,
            allowlist=Allowlist((Entry("https", "target.example", 443, "/"),)),
            budget=budget,
            attestations=[],
            approvals=[
                OperatorApproval("op", TODAY, "local-target", 5.0, "local-p4"),
                OperatorApproval("op", TODAY, "public-target", 0.0, "fixture", "https://target.example"),
            ],
            provider="target",
            est_cost_usd=0.25,
            today=TODAY,
            fake_transport=True,
        )
    assert caught.value.gate == "budget"
    assert calls == []
    assert conn.execute("SELECT COUNT(*) FROM agent_spend").fetchone()[0] == 1


def test_reservation_that_fits_the_remainder_is_allowed() -> None:
    conn = _conn()
    conn.execute("INSERT INTO agent_spend VALUES ('prior', 'target', 0, 4.80, 'incurred')")
    budget = load_shared_budget(conn, CAPS, approval_token(CAPS, SECRET), SECRET)
    ledger = Ledger(conn, budget)
    ledger.reserve("next", "judge", 0.01)
    assert ledger.totals().reserved_usd == pytest.approx(0.01)
    with pytest.raises(BudgetExceeded):
        ledger.reserve("too-much", "target", 0.25)
