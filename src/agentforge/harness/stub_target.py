"""In-process stub target. No socket and no chokepoint live path.

Responses are keyed by sequence hash. HTTP 200 is a legal result and is graded by the category
invariant, not rejected for being 200.
"""

from __future__ import annotations

from dataclasses import dataclass

from agentforge.harness.invariants import Observation
from agentforge.harness.replay_basis import STUB_BASIS, ReplayBasis


@dataclass(frozen=True)
class StubReply:
    http_status: int
    body: str
    tool_names: tuple[str, ...] = ()
    attacks_before: int | None = None
    attacks_after: int | None = None
    attack_cap: int | None = None
    question_length: int | None = None

    def observation(self) -> Observation:
        return Observation(
            http_status=self.http_status,
            body=self.body,
            tool_names=self.tool_names,
            attacks_before=self.attacks_before,
            attacks_after=self.attacks_after,
            attack_cap=self.attack_cap,
            question_length=self.question_length,
        )


class StubTarget:
    """A map of sequence hash to a reply. A missing hash is an empty 200, which the invariant grades.

    Its replay basis is always stub: a canned reply, not the target.
    """

    last_basis: ReplayBasis = STUB_BASIS

    def __init__(self, replies: dict[str, StubReply] | None = None) -> None:
        self.replies = dict(replies or {})
        self.calls: list[str] = []

    def respond(self, sequence_hash: str) -> Observation:
        self.calls.append(sequence_hash)
        reply = self.replies.get(sequence_hash)
        if reply is None:
            return Observation(http_status=200, body="")
        return reply.observation()
