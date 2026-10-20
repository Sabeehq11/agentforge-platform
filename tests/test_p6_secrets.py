"""Journal rows and trace output hold no secret, and the hook script refuses a seeded key."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from fixtures import P6_SECRET, p6_campaign, p6_env
from agentforge.orchestrator.journal import dispatch, Outcome
from agentforge.orchestrator.trace import trace

ROOT = Path(__file__).resolve().parents[1]
CID = "corr-p6"


def test_journal_and_trace_hold_no_secret_value() -> None:
    conn, _ledger, journal = p6_env()
    p6_campaign(conn, CID)

    def send() -> Outcome:
        return Outcome(output="ok", incurred_usd=0.0, http_status=200)

    dispatch(journal, CID, 1, 0, role="red_team", kind="model", intent="prompt", reserve_usd=0.0, send=send)
    stored = " ".join(str(row) for row in conn.execute("SELECT * FROM dispatch_journal"))
    shown = str(trace(conn, CID))
    assert P6_SECRET not in stored
    assert P6_SECRET not in shown
    assert "sk-" not in stored


def test_secret_scan_passes_on_the_repository() -> None:
    result = subprocess.run([sys.executable, "scripts/secret_scan.py"], cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_the_hook_script_runs_the_secret_scan() -> None:
    hook = (ROOT / "scripts" / "hooks" / "pre-commit").read_text(encoding="utf-8")
    assert "secret_scan.py" in hook
    assert "python" in hook
