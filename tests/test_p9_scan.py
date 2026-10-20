"""The dependency-audit gate fails on a planted advisory. No vulnerability feed is consulted."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load():
    spec = importlib.util.spec_from_file_location("self_scan", ROOT / "scripts" / "self_scan.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_a_simulated_advisory_fails_the_audit_gate(monkeypatch, tmp_path: Path) -> None:
    module = _load()
    calls: list[list[str]] = []

    def fake_run(_root: Path, args: list[str]) -> int:
        calls.append(args)
        if "pip_audit" in args:
            print("Found 1 known vulnerability in 1 package")
            print("planted 0.0.0 SIM-0001 9.9.9")
            return 1
        return 0

    monkeypatch.setattr(module, "_run", fake_run)
    assert module.main(["self_scan.py", str(tmp_path)]) == 1
    assert any("pip_audit" in args for args in calls)
    assert any("pytest" in args for args in calls)
    assert any("mypy" in args for args in calls)
    assert any("bandit" in args for args in calls)


def test_a_clean_simulated_scan_exits_zero(monkeypatch, tmp_path: Path, capsys) -> None:
    module = _load()
    monkeypatch.setattr(module, "_run", lambda _root, _args: 0)
    assert module.main(["self_scan.py", str(tmp_path)]) == 0
    assert capsys.readouterr().out.startswith("date: ")
