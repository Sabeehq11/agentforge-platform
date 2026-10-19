"""The architecture check fails closed on each rule and passes on the real repository."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_architecture.py"
REPO = SCRIPT.parents[1]

SUMMARY = "Orchestrator Red Team Judge Documentation " + " ".join(["word"] * 500)
SECTIONS = "\n\n".join(f"## {letter}. Topic\n\n- **Built.** x\n- **Planned.** y" for letter in "ABCDEFGHIJK")
TAIL = "\n\n".join(f"## {h}\n\ntext" for h in ("AI-use disclosure", "API limits and auth", "Pagination", "Deployment note"))
GOOD = f"# Architecture\n\n## Summary\n\n{SUMMARY}\n\n## Diagram\n\n```mermaid\nflowchart LR\n  A-->B\n```\n\n{SECTIONS}\n\n{TAIL}\n"


def run(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(SCRIPT), str(root)], capture_output=True, text=True, check=False)


def write(tmp_path: Path, text: str) -> Path:
    (tmp_path / "ARCHITECTURE.md").write_text(text, encoding="utf-8")
    return tmp_path


def test_good_document_passes(tmp_path: Path) -> None:
    assert run(write(tmp_path, GOOD)).returncode == 0


def test_real_repository_passes() -> None:
    result = run(REPO)
    assert result.returncode == 0, result.stdout


def test_missing_file_fails(tmp_path: Path) -> None:
    assert run(tmp_path).returncode == 1


@pytest.mark.parametrize(
    ("old", "new", "message"),
    [
        (SUMMARY, "Orchestrator Red Team Judge Documentation short", "summary is"),
        (SUMMARY, SUMMARY.replace("Judge ", ""), "does not name the Judge"),
        ("```mermaid", "```text", "no mermaid diagram"),
        ("## E. Topic", "## E2. Topic", "missing section E"),
        ("## Pagination", "## Paging", "missing section: Pagination"),
        ("## Summary", "## Overview", "no Summary section"),
    ],
)
def test_each_rule_fails_closed(tmp_path: Path, old: str, new: str, message: str) -> None:
    result = run(write(tmp_path, GOOD.replace(old, new, 1)))
    assert result.returncode == 1
    assert message in result.stdout


def test_unlabeled_section_fails(tmp_path: Path) -> None:
    text = GOOD.replace("## K. Topic\n\n- **Built.** x\n- **Planned.** y", "## K. Topic\n\nplain text")
    result = run(write(tmp_path, text))
    assert result.returncode == 1
    assert "section K has no Built or Planned label" in result.stdout
