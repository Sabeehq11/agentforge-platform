"""The simulated triage report has ten findings, four classes, and the required evidence fields."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_triage.py"
REPORT = SCRIPT.parents[1] / "evals" / "triage" / "scan-report.json"


def _check():
    spec = importlib.util.spec_from_file_location("check_triage", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.check


check = _check()


def test_committed_report_passes() -> None:
    assert check(REPORT) == []


def test_a_missing_class_fails(tmp_path: Path) -> None:
    data = json.loads(REPORT.read_text(encoding="utf-8"))
    data["findings"] = [item for item in data["findings"] if item["class"] != "false_positive"]
    data["findings"].append(dict(data["findings"][0]))
    path = tmp_path / "scan-report.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    problems = check(path)
    assert any("false_positive" in item for item in problems)


def test_validate_cannot_pair_with_an_offline_gap(tmp_path: Path) -> None:
    data = json.loads(REPORT.read_text(encoding="utf-8"))
    data["findings"][0]["disposition"] = "validate"
    path = tmp_path / "scan-report.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    problems = check(path)
    assert any("not_checkable_offline" in item for item in problems)


def test_script_exits_zero() -> None:
    import subprocess

    result = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stdout
