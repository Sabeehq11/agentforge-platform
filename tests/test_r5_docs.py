"""R5: documentation alignment. Row statuses, preserved evidence, open gaps and wording.

Reads Markdown only. No network. The baseline is the status column recorded at the start of R5, because the working
tree already carried uncommitted edits to PRD_TRACEABILITY.md and HEAD is not the baseline.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TRACE = ROOT / "Docs" / "PRD_TRACEABILITY.md"

BASELINE = {
    "H-1": "gap",
    "H-2": "met",
    "H-3": "met",
    "H-4": "met",
    "H-5": "met",
    "S-1": "partial",
    "S-2": "met",
    "S-3": "met",
    "S-4": "met",
    "S-5": "partial",
    "S-6": "met as a draft",
    "S-7": "partial",
    "M-1": "partial",
    "M-2": "partial",
    "M-3": "partial",
    "M-4": "partial",
    "M-5": "partial",
    "M-6": "partial",
    "M-7": "partial",
    "M-8": "partial",
    "M-9": "partial",
    "M-10": "partial",
    "M-11": "partial",
    "M-12": "partial",
    "D-1": "partial",
    "D-2": "partial",
    "D-3": "partial",
    "D-4": "partial",
    "D-5": "met",
    "D-6": "met",
    "D-7": "partial",
    "D-8": "met",
    "D-9": "met",
    "D-10": "met",
    "D-11": "not started",
    "D-12": "met",
    "D-13": "met",
    "C-1": "met",
    "C-2": "met",
    "C-3": "met",
    "C-4": "met",
    "C-5": "met",
    "C-6": "met",
    "C-7": "met",
    "E-1": "partial",
    "E-2": "partial",
    "E-3": "partial",
    "E-4": "partial",
    "E-5": "met",
    "E-6": "gap",
    "E-7": "met",
    "E-8": "met",
    "E-9": "met",
    "E-10": "met",
    "E-11": "met",
    "E-12": "met",
    "E-13": "met",
    "E-14": "met",
    "E-15": "met",
    "E-16": "met",
    "X-1": "offline-met",
    "X-2": "offline-met",
    "X-3": "unmet",
    "X-4": "unmet",
    "X-5": "offline-met",
    "X-6": "offline-met",
    "X-7": "excluded",
    "X-8": "excluded",
    "X-9": "met",
}
CHANGED = {"D-13", "E-9", "D-8"}
OLD_EVIDENCE = {
    "E-9": "`src/agentforge/safety/phi.py`. `evals/fixtures/synthetic-intake.txt`. `test_phi_blocks_store`. A-001 is still unverified for the running deployment; that does not reopen this row",
    "D-8": "[ACCESS_CONTROL.md](ACCESS_CONTROL.md). Grants at `CampaignLoop` and the suite (`tests/test_p9_access.py`). Direct SQL by the process owner remains possible (ADR-005). Not an identity provider",
    "D-13": "[evals/results/d13-load.json](../evals/results/d13-load.json): 100 of 100, `live: true`, `satisfies_d13: true`, `zero_cost_stub: true`. Orchestration 90.13541795802303s, stub LLM 0.0s across 100 samples, storage 5991.5354876013225 rows/s. Bottleneck is rate-limited orchestration, documented in [LOAD_TEST.md](LOAD_TEST.md) and [ARCHITECTURE.md](../ARCHITECTURE.md). Not a real-provider benchmark. The P8 mock baseline is not this test",
}


def _flat(text: str) -> str:
    return " ".join(text.split())


def _rows() -> dict[str, list[str]]:
    rows: dict[str, list[str]] = {}
    for line in TRACE.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^\| ([A-Z]+-\d+) \| ", line)
        if match and line.count(" | ") >= 4:
            rows[match.group(1)] = line.rstrip().split(" | ")
    return rows


def _evidence(parts: list[str]) -> str:
    return " | ".join(parts[4:]).removesuffix(" |")


def test_status_column_changed_in_exactly_three_rows() -> None:
    rows = _rows()
    assert set(rows) == set(BASELINE)
    changed = {key for key, parts in rows.items() if parts[3] != BASELINE[key]}
    assert changed == CHANGED
    for key in CHANGED:
        assert BASELINE[key] == "met" and rows[key][3] == "partial"


@pytest.mark.parametrize("row_id", sorted(OLD_EVIDENCE))
def test_original_evidence_is_an_unmodified_prefix(row_id: str) -> None:
    assert _evidence(_rows()[row_id]).startswith(OLD_EVIDENCE[row_id])


def test_e9_links_p1_and_d8_links_p2_with_the_date_and_no_closing_word() -> None:
    rows = _rows()
    for row_id, control in (("E-9", "P1"), ("D-8", "P2")):
        added = _evidence(rows[row_id])[len(OLD_EVIDENCE[row_id]) :]
        assert "2026-10-21" in added and re.search(rf"Open control \[?{control}\b", added)
        assert "Downgraded from met" in added
        for word in ("satisfied", "closed", "resolved"):
            assert word not in added.lower()
        other = "P2" if control == "P1" else "P1"
        assert other not in added


def test_d13_names_the_stub_route_and_the_live_half() -> None:
    added = _evidence(_rows()["D-13"])[len(OLD_EVIDENCE["D-13"]) :]
    assert "stub-route" in added and "R13" in added


def test_rows_the_plan_keeps_are_unchanged() -> None:
    rows = _rows()
    expected = {"D-7": "partial", "M-11": "partial", "D-5": "met", "D-10": "met", "M-10": "partial", "E-6": "gap", "E-2": "partial", "H-1": "gap"}
    for key, status in expected.items():
        assert rows[key][3] == status


def test_h3_and_h4_keep_their_status_and_gain_a_local_target_qualifier() -> None:
    rows = _rows()
    for key in ("H-3", "H-4"):
        assert rows[key][3] == "met"
        assert "Local target only" in _evidence(rows[key]) and "R9 and R10" in _evidence(rows[key])


def test_open_gap_table_lists_u1_to_u5_as_gap_with_hosts_and_preconditions() -> None:
    text = TRACE.read_text(encoding="utf-8")
    section = text.split("## Open OWASP verification gaps", 1)[1].split("\n## ", 1)[0]
    table = [line for line in section.splitlines() if re.match(r"^\| U\d ", line)]
    assert [line.split(" | ")[0].strip("| ") for line in table] == ["U1", "U2", "U3", "U4", "U5"]
    for line in table:
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        assert cells[2] == "gap" and cells[3] in {"R7", "R10", "none"} and cells[4]
    flat = _flat(section)
    assert "closes no PRD requirement" in flat and "No host cycle's scope has been amended" in flat
    assert "A candidate host closes nothing" in section
    assert "#open-owasp-verification-gaps" in _evidence(_rows()["M-10"])
    assert _rows()["M-10"][3] == "partial"


def test_ledger_and_gap_table_agree() -> None:
    import json

    ledger = json.loads((ROOT / "evals" / "owasp_coverage.json").read_text(encoding="utf-8"))
    text = TRACE.read_text(encoding="utf-8")
    for gap in ledger["open_gaps"]:
        line = next(item for item in text.splitlines() if item.startswith(f"| {gap['id']} |"))
        assert f"| {gap['candidate_host']} |" in line
        for row_id in gap["ledger_rows"]:
            assert row_id in line


def test_docs_do_not_claim_coverage_or_a_validated_stub_fix() -> None:
    docs = [ROOT / "README.md", ROOT / "ARCHITECTURE.md", ROOT / "evals" / "README.md", *sorted((ROOT / "Docs").glob("*.md"))]
    banned = (
        "a stub-validated fix was validated against the target",
        "client_verified fix is validated",
        "client_verified is a validated fix",
        "ledger satisfies",
        "ledger closes the",
        "offline outcomes satisfy",
        "full llm02 coverage",
        "full llm06 coverage",
        "full llm08 coverage",
        "a09 is covered",
        "a04 is covered",
    )
    for path in docs:
        if path.name == "REMEDIATION_ROADMAP.md":
            continue
        lowered = _flat(path.read_text(encoding="utf-8")).lower()
        for phrase in banned:
            assert phrase not in lowered, (path.name, phrase)


def test_wording_in_the_updated_docs() -> None:
    readme = _flat((ROOT / "README.md").read_text(encoding="utf-8"))
    architecture = _flat((ROOT / "ARCHITECTURE.md").read_text(encoding="utf-8"))
    for text in (readme, architecture):
        assert "response-claim proxy" in text and "U1 to U5" in text and "unverified propert" in text
        assert "constructed facts" in text and "client_verified" in text
    assert "canned reply, not the target" in readme
    assert "OK 11 cases" in readme
    evals_readme = _flat((ROOT / "evals" / "README.md").read_text(encoding="utf-8"))
    assert "H-3 is unmet" not in evals_readme and "does not contain a live result" not in evals_readme
    assert "response-claim proxy" in evals_readme and "closes no PRD requirement" in evals_readme


def test_load_test_and_packets_match_the_repository() -> None:
    defense = (ROOT / "Docs" / "DEFENSE_PACKET.md").read_text(encoding="utf-8")
    assert "Agents that send them are not" not in defense
    ato = (ROOT / "Docs" / "ATO_PACKET.md").read_text(encoding="utf-8")
    assert "Solid edges there are Built" not in ato and "scripted or stub evidence" in ato
    load = (ROOT / "Docs" / "LOAD_TEST.md").read_text(encoding="utf-8")
    assert "`partial`" in load and "R13" in load
    source = (ROOT / "src" / "agentforge" / "evals" / "loadtest.py").read_text(encoding="utf-8")
    assert "already keeps one authenticated session" in source
    assert "satisfies_d13" in source


_NEGATED = re.compile(r"\b(not|no|never|neither|nor|without|cannot|does not|do not)\b", re.IGNORECASE)
_FIX_CLAIMS = ("validated", "confirmed fixed", "verified fix", "proves the fix", "proven fix")


def _units(text: str) -> list[str]:
    return [unit for unit in re.split(r"(?<=[.!?])\s+", _flat(text)) if unit]


def test_no_text_calls_a_client_verified_replay_a_validated_or_confirmed_fix() -> None:
    sources = [ROOT / "README.md", ROOT / "ARCHITECTURE.md", ROOT / "evals" / "README.md", *sorted((ROOT / "Docs").glob("*.md"))]
    sources += [ROOT / "evals" / "owasp_coverage.json", ROOT / "src" / "agentforge" / "harness" / "replay_basis.py"]
    for path in sources:
        if path.name == "REMEDIATION_ROADMAP.md":
            continue
        for unit in _units(path.read_text(encoding="utf-8")):
            lowered = unit.lower()
            if "client_verified" in lowered and any(claim in lowered for claim in _FIX_CLAIMS):
                assert _NEGATED.search(unit), (path.name, unit)


def test_no_text_calls_a01_exercised_without_saying_it_is_offline_only() -> None:
    sources = [ROOT / "README.md", ROOT / "ARCHITECTURE.md", ROOT / "evals" / "README.md", *sorted((ROOT / "Docs").glob("*.md"))]
    for path in sources:
        if path.name == "REMEDIATION_ROADMAP.md":
            continue
        for unit in _units(path.read_text(encoding="utf-8")):
            if re.search(r"\bA01\b", unit) and re.search(r"\bexercised\b", unit, re.IGNORECASE):
                assert re.search(r"offline|no target outcome|not exercised|not `exercised`", unit, re.IGNORECASE), (path.name, unit)
