"""The 100-case baseline uses CampaignLoop under the existing attack cap. No live transport."""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

from agentforge.observe.baseline import run_baseline
from agentforge.safety.budget import load_caps

ROOT = Path(__file__).resolve().parents[1]
FIELDS = (
    "cpu_seconds",
    "peak_rss_bytes",
    "orchestration_latency_seconds",
    "stub_reply_latency_seconds",
    "exploit_storage_rows_per_second",
    "exploit_storage_write_seconds",
)


def test_one_hundred_cases_stay_inside_the_attack_cap() -> None:
    before = (ROOT / "config" / "budget.yaml").read_text(encoding="utf-8")
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys = ON")
    payload = run_baseline(conn)
    assert (ROOT / "config" / "budget.yaml").read_text(encoding="utf-8") == before
    cap = load_caps(ROOT / "config" / "budget.yaml").max_attacks_per_run
    assert payload["live"] is False
    assert payload["path"] == "campaign_loop_stub"
    assert payload["cases"] == 100
    assert payload["satisfies_d13"] is False
    loop = payload["attack_loop"]
    assert loop["cases"] == 100
    assert loop["campaigns"] >= 2
    assert loop["max_attacks_done"] <= cap
    assert conn.execute("SELECT COUNT(*) FROM campaigns").fetchone()[0] == loop["campaigns"]
    assert conn.execute("SELECT COUNT(*) FROM dispatch_journal").fetchone()[0] > 0
    assert conn.execute("SELECT MAX(attacks_done) FROM campaigns").fetchone()[0] <= cap
    assert conn.execute("SELECT COUNT(*) FROM regression_cases").fetchone()[0] == 100
    suite = payload["regression_suite"]
    assert suite["status"] == "done"
    assert suite["cases"] == 100
    for section in (loop, suite):
        for name in FIELDS:
            assert name in section
        assert section["llm_latency"] == "not_measured"
        assert section["stub_reply_latency_label"] == "not_llm_latency"
        assert section["exploit_storage_rows_per_second"] > 0
        assert section["exploit_storage_write_seconds"] > 0
    assert loop["exploit_storage_rows"] == 100
    assert loop["suite_end_to_end_rows"] is None
    assert suite["exploit_storage_rows"] == 300
    assert suite["suite_end_to_end_rows"] == 300
    assert suite["suite_end_to_end_rows_per_second"] > 0
    assert suite["suite_end_to_end_rows_per_second"] != suite["exploit_storage_rows_per_second"]


def test_baseline_script_refuses_live() -> None:
    script = ROOT / "scripts" / "baseline.py"
    result = subprocess.run([sys.executable, str(script), "--live"], capture_output=True, text=True, check=False)
    assert result.returncode == 2
    assert "refused" in result.stderr
    regress = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "regress.py"), "--live"], capture_output=True, text=True, check=False
    )
    assert regress.returncode == 2
    assert "refused" in regress.stderr


def test_live_env_cannot_open_a_socket(monkeypatch: object) -> None:
    os.environ["AGENTFORGE_LIVE"] = "1"
    from agentforge.safety.chokepoint import LIVE_ENABLED, request
    from agentforge.safety.allowlist import Allowlist

    assert LIVE_ENABLED is False
    try:
        request(
            "GET",
            "http://127.0.0.1:9/",
            transport=lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("transport was called")),
            allowlist=Allowlist(),
            budget=None,  # type: ignore[arg-type]
            attestations=[],
            provider="target",
            est_cost_usd=0.0,
            today=__import__("datetime").date(2026, 10, 20),
        )
    except Exception as exc:
        assert "LIVE_ENABLED" in str(exc)
    else:
        raise AssertionError("env flag opened a live path")
