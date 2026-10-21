"""What produced a fix-validation replay, stated next to the label.

A fix-validation line says fixed, not_fixed or regressed. This module says how the runs behind it were produced:

- stub: a StubTarget answered with a canned reply. It is not the target.
- client_verified: a chokepoint client replayed the stored sequence and verify_replay_provenance passed. That proves
  transport and sequence provenance only. It does not show the fix is applied or effective, and it is weaker than a
  journaled execution because client replay sends are not journaled.
- unverified: anything else. A failed check, a fake-transport client, a target that declares no basis, a run row
  written before this field existed, or a mix of bases. A caller that passes no basis gets this label.

The label is not a gate. fixed is still derived from graded pass outcomes, whatever the basis.
"""

from __future__ import annotations

from collections.abc import Collection, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from agentforge.evals.session import SendFact
from agentforge.harness.invariants import Observation

STUB = "stub"
CLIENT_VERIFIED = "client_verified"
UNVERIFIED = "unverified"
BASES = (STUB, CLIENT_VERIFIED, UNVERIFIED)


@dataclass(frozen=True)
class ReplayBasis:
    label: str
    failed_checks: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.label not in BASES:
            raise ValueError("replay basis must be stub, client_verified or unverified")


STUB_BASIS = ReplayBasis(STUB)
NO_BASIS = ReplayBasis(UNVERIFIED, ("basis_undeclared",))


class ReplayTarget(Protocol):
    """Anything that answers a stored sequence by hash. StubTarget and ClientReplayTarget both fit.

    last_basis is read immediately after each respond. A target that does not declare it is read as unverified.
    """

    last_basis: ReplayBasis
    calls: list[str]

    def respond(self, sequence_hash: str) -> Observation: ...


def basis_of(target: object) -> ReplayBasis:
    """The target's declared basis, or unverified when it declares none."""
    declared = getattr(target, "last_basis", None)
    return declared if isinstance(declared, ReplayBasis) else NO_BASIS


def verify_replay_provenance(
    facts: Sequence[SendFact],
    sequence_user_turns: int,
    target_pin: str,
    recorded_pins: Collection[str],
) -> ReplayBasis:
    """client_verified only when every check holds for the facts of one replay send.

    There is no dispatch_journal check. The client seam does not journal replay sends, so this label is weaker than
    recorded_verified for a report source, and the word is not reused for both.
    """
    failed: list[str] = []
    if not facts:
        return ReplayBasis(UNVERIFIED, ("no_facts",))
    if any(fact.fake_transport for fact in facts):
        failed.append("fake_transport")
    if not all(fact.transport_is_real for fact in facts):
        failed.append("transport_not_real")
    if not all(fact.live_enabled for fact in facts):
        failed.append("live_flag_off_at_send")
    purposes = [fact.purpose for fact in facts]
    chats = purposes.count("chat")
    if chats == 0 or "identity" not in purposes[: purposes.index("chat")]:
        failed.append("identity_not_before_first_chat")
    if chats != sequence_user_turns:
        failed.append("chat_count_mismatch")
    if len({fact.origin for fact in facts}) != 1:
        failed.append("mixed_origin")
    if target_pin not in recorded_pins:
        failed.append("pin_not_recorded")
    if failed:
        return ReplayBasis(UNVERIFIED, tuple(failed))
    return ReplayBasis(CLIENT_VERIFIED)


def summarize_basis(evidence: Sequence[dict[str, Any]]) -> ReplayBasis:
    """One basis for the run rows a fix line cites. A missing key or a mix is unverified and says why."""
    if not evidence:
        return ReplayBasis(UNVERIFIED, ("no_runs",))
    labels: list[str] = []
    for item in evidence:
        value = item.get("replay_basis") if isinstance(item, dict) else None
        if value not in BASES:
            return ReplayBasis(UNVERIFIED, ("legacy_row",))
        labels.append(str(value))
    if len(set(labels)) > 1:
        return ReplayBasis(UNVERIFIED, ("mixed",))
    if labels[0] == UNVERIFIED:
        failed: list[str] = []
        for item in evidence:
            for name in item.get("basis_failed") or []:
                if name not in failed:
                    failed.append(str(name))
        return ReplayBasis(UNVERIFIED, tuple(failed) or ("unverified_rows",))
    return ReplayBasis(labels[0])
