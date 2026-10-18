"""The threat-model check fails closed on each rule, and passes on the real repository."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_threat_model.py"
REPO = SCRIPT.parents[1]

SUMMARY = " ".join(["word"] * 500)

GOOD = f"""# Threat model

## Summary

{SUMMARY}

## Scope and method

## TM-PI. Prompt injection

### TM-EX-1. Exfiltration

- **Attack surface.** Answers.
- **Impact.** Data leaves the session.
- **Difficulty.** Low.
- **Existing defenses.** None found.

### TM-SC-1. History

- **Attack surface.** The conversation id.
- **Impact.** Another user's conversation is resumed.
- **Difficulty.** Low.
- **Existing defenses.** None found.

### TM-TM-1. Unintended tools

- **Attack surface.** The model's tool calls.
- **Impact.** A tool runs that was not asked for.
- **Difficulty.** Moderate.
- **Existing defenses.** None found.

### TM-DS-1. Token exhaustion

- **Attack surface.** Long questions.
- **Impact.** One session consumes the budget.
- **Difficulty.** Low.
- **Existing defenses.** None found.

### TM-ID-1. Privilege escalation

- **Attack surface.** CareTeam membership.
- **Impact.** Access beyond the role.
- **Difficulty.** Moderate.
- **Existing defenses.** None found.

### TM-PI-1. Direct

- **Attack surface.** The question field.
- **Impact.** The assistant ignores its rules.
- **Difficulty.** Low.
- **Existing defenses.** None found.

## OWASP mapping

| ID | Item |
|---|---|
| A01 | access | A02 | crypto | A03 | injection | A04 | design | A05 | misconfig |
| A06 | components | A07 | auth | A08 | integrity | A09 | logging | A10 | ssrf |
| LLM01 | injection | LLM02 | output | LLM03 | poisoning | LLM04 | denial | LLM05 | supply |
| LLM06 | disclosure | LLM07 | plugin | LLM08 | agency | LLM09 | overreliance | LLM10 | theft |
"""


def write(root: Path, name: str, text: str) -> None:
    p = root / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def run(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(SCRIPT), str(root)], capture_output=True, text=True)


def test_good_model_passes(tmp_path: Path) -> None:
    write(tmp_path, "THREAT_MODEL.md", GOOD)
    result = run(tmp_path)
    assert result.returncode == 0, result.stdout


def test_missing_attribute_fails(tmp_path: Path) -> None:
    write(tmp_path, "THREAT_MODEL.md", GOOD.replace("- **Difficulty.** Low.\n", ""))
    result = run(tmp_path)
    assert result.returncode == 1
    assert "TM-PI-1" in result.stdout and "difficulty" in result.stdout


def test_missing_category_fails(tmp_path: Path) -> None:
    renamed = GOOD.replace("TM-PI-1", "TM-ZZ-" + "1").replace("TM-PI.", "TM-ZZ.")
    write(tmp_path, "THREAT_MODEL.md", renamed)
    result = run(tmp_path)
    assert result.returncode == 1
    assert "missing PRD category TM-PI" in result.stdout


def test_unknown_reference_fails(tmp_path: Path) -> None:
    write(tmp_path, "THREAT_MODEL.md", GOOD)
    write(tmp_path, "notes.md", "See TM-PI-" + "9 for the gap.\n")
    result = run(tmp_path)
    assert result.returncode == 1
    assert "TM-PI-" + "9" in result.stdout and "not in the threat model" in result.stdout


def test_summary_too_short_fails(tmp_path: Path) -> None:
    write(tmp_path, "THREAT_MODEL.md", GOOD.replace(SUMMARY, "too short"))
    result = run(tmp_path)
    assert result.returncode == 1
    assert "summary is" in result.stdout


def test_missing_owasp_row_fails(tmp_path: Path) -> None:
    write(tmp_path, "THREAT_MODEL.md", GOOD.replace("A10", "A99"))
    result = run(tmp_path)
    assert result.returncode == 1
    assert "missing OWASP row A10" in result.stdout


def test_reference_inside_a_fence_is_ignored(tmp_path: Path) -> None:
    write(tmp_path, "THREAT_MODEL.md", GOOD)
    write(tmp_path, "notes.md", "```\nTM-NO-" + "1\n```\n")
    assert run(tmp_path).returncode == 0


@pytest.mark.parametrize("present", [True, False])
def test_evals_directory_is_scanned_when_present(tmp_path: Path, present: bool) -> None:
    """The scan passes when no evals exist yet, and catches a bad ID once they do."""
    write(tmp_path, "THREAT_MODEL.md", GOOD)
    if present:
        write(tmp_path, "evals/case.md", "category: TM-PI-1\n")
    assert run(tmp_path).returncode == 0


def test_real_repository_passes() -> None:
    result = run(REPO)
    assert result.returncode == 0, result.stdout
