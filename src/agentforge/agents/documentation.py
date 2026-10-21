"""Documentation agent. A template, not a model. It drafts and does not publish.

The model for this role stays TBD. Nothing here calls a provider or the target. The run_logs row
uses the campaign correlation id. There is no dispatch-journal role for this agent.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agentforge.contracts.messages import ConfirmedExploit
from agentforge.contracts.validate import validate
from agentforge.orchestrator.provenance import FIXTURE, UNVERIFIED as PROVENANCE_UNVERIFIED, VERIFIED, Provenance
from agentforge.orchestrator.state import log_run, now_iso
from agentforge.safety.content import require_storable_sequence
from agentforge.store.access import Grant, require_grant
from agentforge.safety.phi import require_clean
from agentforge.store.records import CATEGORIES, SEVERITIES, IncompleteRecord, StoreError, sequence_hash

if TYPE_CHECKING:  # harness/__init__ imports suite, which imports this module, so the type is not imported at runtime
    from agentforge.harness.replay_basis import ReplayBasis

STUB = "stub"
CLIENT_VERIFIED = "client_verified"
UNVERIFIED = "unverified"

REQUIRED = (
    "exploit_id",
    "severity",
    "category",
    "clinical_impact",
    "minimal_sequence",
    "observed_behavior",
    "expected_behavior",
    "proposed_remediation",
    "status",
)


def draft_report(
    conn: sqlite3.Connection,
    exploit: ConfirmedExploit,
    grant: Grant | None = None,
    *,
    held: bool = False,
    provenance: Provenance | None = None,
) -> str:
    """Validate and insert one draft. A second draft for the same exploit returns the existing id.

    provenance is how the source sequence was executed. None means a platform fixture. The label is verified by
    orchestrator.provenance from send-time facts. It is never taken from a transport flag here.
    """
    require_grant(grant, "documentation")
    validate("confirmed_exploit", exploit)
    missing = [name for name in REQUIRED if not exploit.get(name)]
    if missing:
        raise IncompleteRecord("missing required field: " + ", ".join(missing))
    if exploit["severity"] not in SEVERITIES or exploit["category"] not in CATEGORIES:
        raise IncompleteRecord("severity or category is not allowed")
    if exploit["status"] != "draft":
        raise StoreError("an agent cannot write a report that is not a draft")
    parent = conn.execute(
        "SELECT sequence_hash, status FROM exploits WHERE id = ?", (exploit["exploit_id"],)
    ).fetchone()
    if parent is None:
        raise IncompleteRecord("documentation cannot insert an exploit the Judge did not confirm")
    digest = sequence_hash(exploit["minimal_sequence"])
    if digest != parent[0]:
        raise StoreError("report sequence does not match the confirmed exploit")
    existing = conn.execute("SELECT id FROM reports WHERE exploit_id = ?", (exploit["exploit_id"],)).fetchone()
    if existing is not None:
        return str(existing[0])
    report_id = f"rpt-{exploit['exploit_id']}"[:64]
    remediation = str(exploit["proposed_remediation"])
    body = render(
        report_id=report_id,
        exploit=dict(exploit),
        publication="draft",
        remediation_status="proposed",
        fix_validation="not_run",
        pin=None,
        run_ids="",
        provenance=provenance,
    )
    require_storable_sequence(exploit["minimal_sequence"])
    require_clean(body)
    when = now_iso()
    with conn:
        conn.execute(
            """
            INSERT INTO reports (
                id, exploit_id, correlation_id, body, sequence_hash, status, remediation_status,
                remediation_text, remediation_hash, fix_validation, evidence_run_ids, held, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, 'draft', 'proposed', ?, ?, 'not_run', '', ?, ?, ?)
            """,
            (
                report_id,
                exploit["exploit_id"],
                exploit["correlation_id"],
                body,
                digest,
                remediation,
                hashlib.sha256(remediation.encode("utf-8")).hexdigest(),
                1 if held else 0,
                when,
                when,
            ),
        )
        log_run(conn, exploit["correlation_id"], "documentation", "done", commit=False)
    return report_id


def render(
    *,
    report_id: str,
    exploit: dict[str, Any],
    publication: str,
    remediation_status: str,
    fix_validation: str,
    pin: str | None,
    run_ids: str,
    provenance: Provenance | None = None,
    replay_basis: ReplayBasis | tuple[ReplayBasis, ReplayBasis] | None = None,
) -> str:
    """Fixed headings, so a reviewer can replay the turns without the agent that wrote them."""
    turns = json.dumps(exploit["minimal_sequence"], sort_keys=True)
    fix = fix_validation_line(fix_validation, pin, run_ids, replay_basis)
    return "\n".join(
        [
            f"Report: {report_id}",
            f"Severity: {exploit['severity']}",
            f"Category: {exploit['category']}",
            f"Clinical impact: {exploit['clinical_impact']}",
            f"Minimal sequence: {turns}",
            f"Observed: {exploit['observed_behavior']}",
            f"Expected: {exploit['expected_behavior']}",
            f"Remediation: {exploit['proposed_remediation']}",
            f"Publication status: {publication}",
            f"Remediation status: {remediation_status}",
            fix,
            source_line(provenance),
        ]
    )


FIXTURE_SOURCE_LINE = "Live target: no. This draft was produced from a platform fixture, not a deployed finding."


def source_line(provenance: Provenance | None) -> str:
    """The one line that says where the source sequence came from. It follows the verified label only."""
    if provenance is None or provenance.label == FIXTURE:
        return FIXTURE_SOURCE_LINE
    if provenance.label == PROVENANCE_UNVERIFIED:
        checks = ", ".join(provenance.failed) or "unspecified"
        return (
            f"Live target: unverified. Provenance incomplete: {checks}. "
            "Not a deployed finding until provenance is verified."
        )
    if provenance.label == VERIFIED:
        return (
            f"Live target: yes. Provenance verified: executor transcript {provenance.transcript_id}, "
            f"{provenance.steps} completed target steps in sequence {provenance.sequence_id}, "
            f"identity check before first chat, pin {provenance.pin}, origin {provenance.origin}. "
            "This label does not assert the origin is the public deployed URL. "
            "This is a draft a human must approve."
        )
    raise ValueError("unknown provenance label")


def fix_validation_line(
    label: str,
    pin: str | None,
    run_ids: str,
    basis: ReplayBasis | tuple[ReplayBasis, ReplayBasis] | None = None,
) -> str:
    """The one fix-validation sentence. A regression names both pins and both run-id sets.

    Every line that cites runs also names how those runs were produced. A caller that passes no basis gets
    unverified, so a stronger label cannot come from omission. not_run cites no run, so it states no basis.
    """
    if pin and "," in pin and label == "regressed":
        previous, current = pin.split(",", 1)
        ids = [item for item in run_ids.split(",") if item]
        half = len(ids) // 2
        previous_ids, current_ids = ",".join(ids[:half]), ",".join(ids[half:])
        line = (
            f"Fix validation: {label}; previous pin {previous}; runs {previous_ids}; "
            f"pin {current}; runs {current_ids}"
        )
        return f"{line}; {_basis_suffix(label, basis)}"
    line = f"Fix validation: {label}"
    if pin:
        line = f"{line}; pin {pin}; runs {run_ids}"
    if label == "not_run":
        return line
    return f"{line}; {_basis_suffix(label, basis)}"


def _no_basis() -> ReplayBasis:
    from agentforge.harness.replay_basis import ReplayBasis

    return ReplayBasis(UNVERIFIED, ("basis_not_supplied",))


_CLIENT_QUALIFIER = "transport and sequence only; does not show the fix is applied or effective"


def _basis_suffix(label: str, basis: ReplayBasis | tuple[ReplayBasis, ReplayBasis] | None) -> str:
    unknown = _no_basis()
    if label == "regressed":
        previous, current = basis if isinstance(basis, tuple) else (basis or unknown, basis or unknown)
        text = f"replay basis previous {previous.label}, current {current.label}"
        if CLIENT_VERIFIED in (previous.label, current.label):
            text += f" (client_verified: {_CLIENT_QUALIFIER})"
        return text
    single = basis if basis is not None and not isinstance(basis, tuple) else unknown
    if single.label == STUB:
        return "replay basis stub (canned reply, not the target)"
    if single.label == CLIENT_VERIFIED:
        return f"replay basis client_verified ({_CLIENT_QUALIFIER})"
    return f"replay basis unverified ({', '.join(single.failed_checks) or 'no basis recorded'})"


def write_report_markdown(directory: Path, report_id: str, body: str) -> Path:
    """Write the stored body to a markdown file. The file is the body, so the two cannot disagree."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{report_id}.md"
    path.write_text(body if body.endswith("\n") else body + "\n", encoding="utf-8")
    return path


def is_false_positive(verdict: dict[str, Any], evidence: str, canary: str | None) -> bool:
    """Hold a review flag, or a canary quote that was not obedience, at draft.

    A ConfirmedExploit has no verdict field. The recorded target text is the evidence. A quote of the canary
    without an obedience marker is held even when the Judge stored a draft fail.
    """
    from agentforge.evals.graders import canary_obeyed

    if verdict.get("needs_human_review") is True:
        return True
    if canary and canary in evidence and not canary_obeyed(evidence, canary):
        return True
    return False
