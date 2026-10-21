"""Replay a stored sequence through the chokepoint client. Not a stub, and not a socket of its own.

ClientReplayTarget wraps an existing SessionClient, so every request still passes the allowlist, the budget, the
rate cap, the attestation check and the LIVE_ENABLED gate. While LIVE_ENABLED is false a non-fake client is refused
before any request, which surfaces here as ReplayRefused. Nothing here sets a switch or opens a connection.

The replay rule is not journaled. A claimed handoff that was interrupted is therefore not resumed through this seam:
the loop halts for operator review so an unjournaled send is never repeated.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from agentforge.evals.login import LoginRequest
from agentforge.evals.session import SessionClient, SessionError, TargetStatusError
from agentforge.harness.invariants import Observation
from agentforge.harness.replay_basis import ReplayBasis, verify_replay_provenance
from agentforge.safety.chokepoint import RefusedByChokepoint
from agentforge.safety.identity import IdentityMismatch


class ReplayRefused(Exception):
    """A client replay could not run or could not finish. No pass is recorded for it. The reason names a class only."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class ClientReplayTarget:
    """Replays exploits.reproduction_steps through a SessionClient, one identity-checked session per sequence."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        client: SessionClient,
        credentials: LoginRequest,
        fixture_pid: str,
        target_pin: str,
    ) -> None:
        self._conn = conn
        self._client = client
        self._credentials = credentials
        self._pid = fixture_pid
        self._pin = target_pin
        self.calls: list[str] = []
        self.last_basis: ReplayBasis = ReplayBasis("unverified", ("no_replay_yet",))

    def respond(self, sequence_hash: str) -> Observation:
        self.calls.append(sequence_hash)
        turns = self._turns(sequence_hash)
        start = len(self._client.facts)
        status: int | None = None
        text = ""
        try:
            self._client.verify_identity()
            self._client.login(self._credentials)
            self._client.read_dock()
            self._client.open_patient(self._pid)
            self._client.session.conversation_id = None  # one conversation per replayed sequence
            for turn in turns:
                chat = self._client.post_chat(turn)
                status, text = chat.status, chat.text
        except RefusedByChokepoint as exc:
            raise ReplayRefused(f"chokepoint gate {exc.gate}") from exc
        except IdentityMismatch as exc:
            raise ReplayRefused("identity_mismatch") from exc
        except TargetStatusError as exc:
            raise ReplayRefused(f"target status {exc.status}") from exc
        except SessionError as exc:
            raise ReplayRefused("session failure") from exc
        self.last_basis = verify_replay_provenance(
            self._client.facts[start:], len(turns), self._pin, self._recorded_pins()
        )
        return Observation(http_status=status, body=text)

    def _turns(self, sequence_hash: str) -> list[str]:
        row = self._conn.execute(
            "SELECT reproduction_steps FROM exploits WHERE sequence_hash = ?", (sequence_hash,)
        ).fetchone()
        if row is None:
            raise ReplayRefused("no stored sequence for this hash")
        try:
            sequence: Any = json.loads(str(row[0]))
        except json.JSONDecodeError as exc:
            raise ReplayRefused("stored sequence is not readable") from exc
        turns = [
            str(item["content"])
            for item in (sequence.get("turns", []) if isinstance(sequence, dict) else [])
            if isinstance(item, dict) and item.get("role") == "user" and item.get("content")
        ]
        if not turns:
            raise ReplayRefused("stored sequence has no user turn")
        return turns

    def _recorded_pins(self) -> set[str]:
        rows = self._conn.execute(
            "SELECT target_pin FROM version_baselines UNION SELECT target_pin FROM version_handoffs"
        ).fetchall()
        return {str(row[0]) for row in rows}
