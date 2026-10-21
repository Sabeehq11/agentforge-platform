"""R6: interpretation records only. Markdown is read, nothing else. No network.

An interpretation is a reading of an ambiguous PRD sentence. It is not proof of compliance and it closes no gap.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DECISIONS = (ROOT / "Docs" / "DECISIONS.md").read_text(encoding="utf-8")
TRACE = (ROOT / "Docs" / "PRD_TRACEABILITY.md").read_text(encoding="utf-8")

CONTROL_OPEN = {"D-015": "P1", "D-017": "P2", "D-018": "P3"}
DECIDED = ("D-016", "D-019", "D-020", "D-021", "D-022")
FIELDS = (
    "**PRD sentence and page.**",
    "**Reading.**",
    "**Evidence that exists today.**",
    "**Residual risk.**",
    "**Will not build.**",
    "**Reopen trigger.**",
    "**Requirement rows touched and their status.**",
)
CLOSING = re.compile(r"\b(satisfies|satisfied|met|closed|resolved|compliant|decided)\b", re.IGNORECASE)
NEGATION = re.compile(r"\b(not|never|no|neither|nor|none|cannot|without)\b", re.IGNORECASE)
CONTROL_TOKEN = re.compile(r"\b(G27|G14|G15|P1|P2|P3)\b")


def _r6_text() -> str:
    start = DECISIONS.index("### Recorded, control open")
    end = DECISIONS.index("## 2. Open questions")
    return DECISIONS[start:end]


def _entries() -> dict[str, str]:
    text = _r6_text()
    parts = re.split(r"^#### (D-\d{3}) ", text, flags=re.MULTILINE)
    return {parts[i]: parts[i + 1] for i in range(1, len(parts), 2)}


def _flat(text: str) -> str:
    return " ".join(text.split())


def test_entries_d015_to_d022_exist_with_every_field() -> None:
    entries = _entries()
    assert sorted(entries) == ["D-015", "D-016", "D-017", "D-018", "D-019", "D-020", "D-021", "D-022"]
    for key, body in entries.items():
        head = body.splitlines()[0]
        assert "(interpretation)" in head, key
        for field in FIELDS:
            assert field in body, (key, field)
        assert "**Not proven" in body, key


def test_g27_g14_g15_are_recorded_control_open_not_decided() -> None:
    entries = _entries()
    for key, control in CONTROL_OPEN.items():
        assert "recorded, control open" in entries[key].splitlines()[0]
        assert f"({control})" in entries[key].splitlines()[0]
        # Not proven is the first field after the heading.
        assert "**Not proven (first).**" in entries[key].split("**PRD sentence")[0]
    decided_table = DECISIONS.split("## 1. Decided", 1)[1].split("### Recorded, control open", 1)[0]
    for key in CONTROL_OPEN:
        assert not re.search(rf"^\| {key} \|", decided_table, flags=re.MULTILINE)
    for key in DECIDED:
        assert re.search(rf"^\| {key} \| \*\*\(interpretation\)\*\*", decided_table, flags=re.MULTILINE)
    control_table = DECISIONS.split("### Recorded, control open", 1)[1].split("### Interpretation entries", 1)[0]
    for key, control in CONTROL_OPEN.items():
        row = next(line for line in control_table.splitlines() if line.startswith(f"| {key} |"))
        assert "recorded, control open" in row and control in row


def test_no_interpretation_says_it_satisfies_a_sentence() -> None:
    entries = _entries()
    for key, body in entries.items():
        scrubbed = re.sub(r"- \*\*Requirement rows touched and their status\.\*\*.*?(?=\n- \*\*|\n\n|\Z)", "", body, flags=re.DOTALL) if key in {"D-016", "D-021"} else body
        for sentence in re.split(r"(?<=[.!?])\s+|\n", scrubbed):
            if re.search(r"\bsatisf", sentence, re.IGNORECASE):
                assert NEGATION.search(sentence), (key, sentence)
        assert "we read" in body.lower() or "reading." in body.lower()


def test_never_close_grep_over_the_r6_text() -> None:
    texts = [_r6_text(), TRACE.split("## Interpretation register", 1)[1].split("## How to update this file", 1)[0]]
    decided_rows = "\n".join(line for line in DECISIONS.splitlines() if re.match(r"^\| D-0(1[5-9]|2[0-2]) \|", line))
    texts.append(decided_rows)
    for text in texts:
        for unit in re.split(r"(?<=[.!?])\s+|\n", text):
            if CONTROL_TOKEN.search(unit) and CLOSING.search(unit):
                assert NEGATION.search(unit), unit


def test_open_controls_register_lists_p1_p2_p3_as_open_only() -> None:
    section = DECISIONS.split("### Open-controls register", 1)[1].split("### Residual-risk register", 1)[0]
    rows = [line for line in section.splitlines() if re.match(r"^\| P[123],", line)]
    assert [line.split(",")[0].strip("| ") for line in rows] == ["P1", "P2", "P3"]
    for line in rows:
        assert line.rstrip().endswith("| open |")
        assert not CLOSING.search(line.split("|")[1])
    flat = _flat(section).lower()
    for word in ("closed", "resolved", "decided"):
        assert word not in flat


def test_residual_register_carries_every_r3_r4_limit_and_every_gap() -> None:
    register = _flat(DECISIONS.split("### Residual-risk register", 1)[1].split("## 2. Open questions", 1)[0])
    for needle in (
        "P1, P2 and P3",
        "U1:",
        "U2:",
        "U3:",
        "U4:",
        "U5:",
        "empty 200 body",
        "does not gate `fixed`",
        "R11",
        "R12",
        "no journal check",
        "not a validated fix",
        "constructed facts",
        "response-claim proxy",
        "resumed campaign",
    ):
        assert needle in register, needle


def test_owasp_entry_marks_nothing_covered_and_keeps_u1_to_u5_open() -> None:
    entry = _flat(_entries()["D-022"])
    for needle in ("U1", "U2", "U3", "U4", "U5", "partially exercised", "unverified properties", "response-claim proxy"):
        assert needle in entry
    assert "does not close" in entry or "None of this closes" in entry
    assert "No cycle has been amended" in entry


def test_traceability_register_and_row_notes() -> None:
    register = TRACE.split("## Interpretation register", 1)[1].split("## How to update this file", 1)[0]
    for key in (*CONTROL_OPEN, *DECIDED):
        assert re.search(rf"^\| {key} \|", register, flags=re.MULTILINE)
    for key, control in CONTROL_OPEN.items():
        row = next(line for line in register.splitlines() if line.startswith(f"| {key} |"))
        assert f"recorded, control open ({control})" in row
    rows = {m.group(1): line for line in TRACE.splitlines() if (m := re.match(r"^\| ([A-Z]+-\d+) \| ", line))}
    assert "Met under interpretation [D-016]" in rows["D-5"] and rows["D-5"].split(" | ")[3] == "met"
    assert "Met under interpretation [D-021]" in rows["D-10"] and rows["D-10"].split(" | ")[3] == "met"
    assert "Control unproven, see [D-015]" in rows["D-7"] and "Control unproven, see [D-017]" in rows["M-11"]
    for key in ("E-9", "D-8", "D-7", "M-11"):
        assert "met under interpretation" not in rows[key].lower()
    assert rows["E-9"].split(" | ")[3] == "partial" and rows["D-8"].split(" | ")[3] == "partial"
    assert "[P1](DECISIONS.md#open-controls-register)" in rows["E-9"]
    assert "[P2](DECISIONS.md#open-controls-register)" in rows["D-8"]
    for key, status in {"E-6": "gap", "E-2": "partial", "M-11": "partial", "H-1": "gap", "D-7": "partial"}.items():
        assert rows[key].split(" | ")[3] == status


@pytest.mark.parametrize("anchor", ["open-controls-register", "interpretation-entries-r6-2026-10-21"])
def test_traceability_links_resolve_to_a_decisions_heading(anchor: str) -> None:
    slugs = set()
    for line in DECISIONS.splitlines():
        match = re.match(r"^#+ (.*)$", line)
        if match:
            slugs.add(re.sub(r"[^a-z0-9 -]", "", match.group(1).lower()).replace(" ", "-"))
    assert anchor in slugs
    assert f"DECISIONS.md#{anchor}" in TRACE


def test_decisions_text_never_marks_a_u_item_or_ledger_row_satisfied() -> None:
    text = _flat(_r6_text())
    for sentence in re.split(r"(?<=[.!?])\s+", text):
        if re.search(r"\b(U[1-5]|A04|A09)\b", sentence) and re.search(r"\b(covered|satisfied|met|closed)\b", sentence, re.IGNORECASE):
            assert NEGATION.search(sentence), sentence
