"""Human gates. Publication and remediation are different records. Neither applies a patch.

P7 checks that an agent cannot skip a gate. P9 checks which human the record names. An approval
file is the same operator-approval shape, with a purpose bound to one report.
"""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import yaml

from agentforge.orchestrator.state import now_iso
from agentforge.store.records import StoreError

PUBLISH = "publish_finding"
REMEDIATE = "authorize_remediation"
CRITICAL = ("critical", "high")


class ApprovalRefused(StoreError):
    """The record does not authorize this act. The row is unchanged."""


@dataclass(frozen=True)
class GateApproval:
    approved_by: str
    approved_on: date
    purpose: str
    report_id: str
    bound: str


def load_gate_approvals(path: str | Path) -> list[GateApproval]:
    """A missing file yields no approvals. A malformed row is skipped."""
    try:
        data: Any = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return []
    if not isinstance(data, dict) or not isinstance(data.get("approvals"), list):
        return []
    out: list[GateApproval] = []
    for raw in data["approvals"]:
        try:
            on = raw["approved_on"]
            if not isinstance(on, date):
                on = date.fromisoformat(str(on))
            purpose = str(raw["purpose"])
            if purpose not in (PUBLISH, REMEDIATE):
                continue
            out.append(
                GateApproval(
                    approved_by=str(raw["approved_by"]).strip(),
                    approved_on=on,
                    purpose=purpose,
                    report_id=str(raw["report_id"]),
                    bound=str(raw["bound"]),
                )
            )
        except (KeyError, TypeError, ValueError):
            continue
    return out


def _fresh(item: GateApproval, *, today: date, max_age_days: int) -> bool:
    return bool(item.approved_by) and item.approved_on <= today and today - item.approved_on <= timedelta(days=max_age_days)


def _match(
    approvals: list[GateApproval],
    *,
    purpose: str,
    report_id: str,
    bound: str,
    today: date,
) -> GateApproval | None:
    for item in approvals:
        if item.purpose == purpose and item.report_id == report_id and item.bound == bound and _fresh(item, today=today, max_age_days=7):
            return item
    return None


def submit_for_approval(conn: sqlite3.Connection, report_id: str) -> None:
    """Move a draft to pending_approval. Does not change remediation status."""
    row = conn.execute("SELECT status, held, exploit_id FROM reports WHERE id = ?", (report_id,)).fetchone()
    if row is None:
        raise ApprovalRefused("no such report")
    if int(row[1]) == 1:
        raise ApprovalRefused("a held false positive stays at draft")
    if row[0] != "draft":
        raise ApprovalRefused("only a draft can be submitted")
    with conn:
        conn.execute("UPDATE reports SET status = 'pending_approval', updated_at = ? WHERE id = ?", (now_iso(), report_id))
        conn.execute(
            "UPDATE exploits SET status = 'pending_approval' WHERE id = ? AND status = 'draft'",
            (row[2],),
        )


def decide(
    conn: sqlite3.Connection,
    report_id: str,
    decision: str,
    approvals: list[GateApproval],
    *,
    today: date,
) -> None:
    """Publish or reject. A remediation approval is refused here. Critical and high need publish_finding."""
    if decision not in ("published", "rejected"):
        raise ApprovalRefused("decision must be published or rejected")
    row = conn.execute(
        "SELECT status, exploit_id FROM reports WHERE id = ?", (report_id,)
    ).fetchone()
    if row is None or row[0] != "pending_approval":
        raise ApprovalRefused("publication requires pending_approval")
    severity = conn.execute("SELECT severity FROM exploits WHERE id = ?", (row[1],)).fetchone()
    if severity is None:
        raise ApprovalRefused("report has no exploit")
    if decision == "published" and str(severity[0]) in CRITICAL:
        matched = _match(approvals, purpose=PUBLISH, report_id=report_id, bound=str(severity[0]), today=today)
        if matched is None:
            raise ApprovalRefused("critical or high publication needs a publish_finding approval for this report and severity")
    with conn:
        conn.execute("UPDATE reports SET status = ?, updated_at = ? WHERE id = ?", (decision, now_iso(), report_id))
        conn.execute("UPDATE exploits SET status = ? WHERE id = ?", (decision, row[1]))


def request_remediation(conn: sqlite3.Connection, report_id: str) -> None:
    """Propose only. Does not publish and does not write a patch."""
    row = conn.execute("SELECT remediation_status FROM reports WHERE id = ?", (report_id,)).fetchone()
    if row is None or row[0] != "proposed":
        raise ApprovalRefused("remediation can be requested only from proposed")
    with conn:
        conn.execute(
            "UPDATE reports SET remediation_status = 'pending_authorization', updated_at = ? WHERE id = ?",
            (now_iso(), report_id),
        )


def authorize_remediation(
    conn: sqlite3.Connection,
    report_id: str,
    decision: str,
    approvals: list[GateApproval],
    *,
    today: date,
) -> None:
    """Authorize or reject the stored proposal. A publish_finding record is refused. No patch is applied."""
    if decision not in ("authorized", "rejected"):
        raise ApprovalRefused("remediation decision must be authorized or rejected")
    row = conn.execute(
        "SELECT remediation_status, remediation_hash, status FROM reports WHERE id = ?", (report_id,)
    ).fetchone()
    if row is None or row[0] != "pending_authorization":
        raise ApprovalRefused("remediation is not pending authorization")
    if decision == "authorized":
        matched = _match(approvals, purpose=REMEDIATE, report_id=report_id, bound=str(row[1]), today=today)
        if matched is None:
            raise ApprovalRefused("remediation needs an authorize_remediation approval bound to the proposal hash")
    with conn:
        conn.execute(
            "UPDATE reports SET remediation_status = ?, updated_at = ? WHERE id = ?",
            (decision, now_iso(), report_id),
        )


def proposal_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
