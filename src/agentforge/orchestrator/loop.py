"""The orchestrator loop. Wires Orchestrator, Red Team, executor, Judge and Documentation under one correlation ID.

Documentation drafts from a confirmed exploit. It does not call a model. A pending version handoff replays the
full eligible regression suite on the offline stub before the next attack. A missing stub is a typed halt, not a
skip. Every external effect is a journaled step. A phase change and its run_logs row are one transaction.
The executor step is logged with the existing role `harness`. dispatch_journal.role carries `executor`.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentforge.agents.judge import RulesJudge, TranscriptRejected, require_transcript, target_text
from agentforge.agents.novelty import NoveltyReport, sequence_distance
from agentforge.agents.red_team_generator import Generated, GenerationStopped, ModelClient, Parent, RedTeamGenerator, load_parent
from agentforge.contracts.messages import AttackResult, CampaignRequest
from agentforge.contracts.validate import ContractError, validate
from agentforge.evals.cases import Case
from agentforge.orchestrator.drift_gate import JudgeDrift, check_judge_drift
from agentforge.orchestrator.journal import Journal, UnknownOutcome
from agentforge.orchestrator.policy import Config, validate_variants
from agentforge.orchestrator.priority import next_category
from agentforge.orchestrator.retry import Halt
from agentforge.orchestrator.sequence import PreflightRefused, SequenceResult, SequenceRunner
from agentforge.orchestrator.signals import record_signal
from agentforge.orchestrator.state import (
    bump,
    halt,
    log_run,
    request_of,
    require_campaign,
    resume_campaign,
    set_phase,
    set_scores,
)
from agentforge.orchestrator.stop import apply_redirect, decide
from agentforge.orchestrator.versions import observe_version
from agentforge.agents.documentation import draft_report, is_false_positive
from agentforge.harness.invariants import _CANARY, invariant_id_for
from agentforge.harness.stub_target import StubTarget
from agentforge.harness.suite import claim_handoff, run_suite
from agentforge.store.access import issue_grant
from agentforge.store.records import DuplicateSequence, insert_exploit, insert_regression_case

JUDGE_RESERVE_USD = 0.0
_CATEGORIES = ("TM-PI", "TM-EX", "TM-SC", "TM-TM", "TM-DS", "TM-ID")


@dataclass
class RunOutcome:
    correlation_id: str
    phase: str
    error_code: str | None = None
    detail: str = ""
    sequences: int = 0
    verdicts: list[dict[str, Any]] = field(default_factory=list)
    novelty: dict[str, object] | None = None


class CampaignLoop:
    """One campaign at a time. next_request() returns the ranked order, or None when nothing is attackable."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        journal: Journal,
        config: Config,
        generator: RedTeamGenerator,
        runner: SequenceRunner,
        judge: RulesJudge,
        seeds: Sequence[Case],
        *,
        identity_verified: bool = True,
        observed_pin: str | None = None,
        stub: StubTarget | None = None,
        reports_dir: Path | None = None,
    ) -> None:
        self._conn = conn
        self._journal = journal
        self._config = config
        self._generator = generator
        self._runner = runner
        self._grader = judge
        self._seeds = tuple(seeds)
        self._identity_verified = identity_verified
        self._observed_pin = observed_pin
        self._stub = stub
        self._reports_dir = reports_dir
        self._step = 0
        self._verdicts: list[dict[str, Any]] = []

    def next_request(self, correlation_id: str) -> CampaignRequest | None:
        """Rank from persisted evidence only. None means nothing is attackable."""
        campaign = require_campaign(self._conn, correlation_id)
        request = request_of(campaign)
        attackable = frozenset(c.category for c in self._seeds)
        ranking = next_category(
            self._conn, str(campaign["system_version"]), attackable, self._config.weights, self._config.fallback_order
        )
        set_scores(self._conn, correlation_id, ranking.as_audit())
        chosen = ranking.first
        if chosen is None:
            return None
        body = dict(request)
        body["category"] = chosen
        validate("campaign_request", body)
        return body  # type: ignore[return-value]

    def run(self, correlation_id: str, *, mode: str | None = None, variants: int | None = None) -> RunOutcome:
        """Drive one campaign to done or halted. An unknown outcome halts retryable and is never replayed.

        mode=None selects per attack: mutation when an unclaimed Judge partial is eligible, otherwise the campaign's
        stored requested_mode (multi_turn) or novel (one turn). An explicit mode is used as given. resume passes
        None, so the stored request is what a resumed campaign continues with.
        """
        campaign = require_campaign(self._conn, correlation_id)
        request = request_of(campaign)
        self._check_identity(correlation_id, request)
        if variants is not None:
            return self._variants(correlation_id, variants)
        return self._ordinary(correlation_id, mode)

    def resume(self, correlation_id: str, *, accept_unknown: str | None = None) -> RunOutcome:
        """Reconcile, then continue. A sent or unknown row halts unless the operator accepts that call id."""
        campaign = resume_campaign(self._conn, correlation_id)
        request = request_of(campaign)
        self._check_identity(correlation_id, request)
        if accept_unknown is not None:
            self._journal.accept_unknown(accept_unknown)
        try:
            self._journal.resume_check(correlation_id)
        except UnknownOutcome as exc:
            # Reconciliation found a call that may have left the process. Nothing more is sent, so no identity GET.
            return self._stop(correlation_id, "target_unreachable", True, f"unknown_outcome {exc.call_id}")
        self._require_identity(correlation_id)
        return self._ordinary(correlation_id, None)

    # identity and version ----------------------------------------------------------------------------------
    def _check_identity(self, correlation_id: str, request: CampaignRequest) -> None:
        if not self._identity_verified:
            self._stop(correlation_id, "target_unreachable", False, "identity_mismatch")
            raise ContractError("campaign_request", "identity_mismatch")
        pin = self._observed_pin or request["target_pin"]
        observation = observe_version(self._conn, pin, identity_verified=True, correlation_id=correlation_id)
        if observation.action == "refused":
            self._stop(correlation_id, "target_unreachable", False, observation.detail)
            raise ContractError("campaign_request", observation.detail)
        self._replay_pending(correlation_id)

    def _require_identity(self, correlation_id: str) -> None:
        """Re-verify the target before any live call a resume might make.

        Reconciliation itself sends nothing. An in-memory or fixture transport is not a live target, so that path
        does not open a socket. A live client is checked here; a mismatch halts and sends nothing after it.
        """
        client = self._runner._client  # noqa: SLF001 — the session client is the identity gate
        if client.fake_transport:
            return
        try:
            client.verify_identity()
        except Exception as exc:
            self._stop(correlation_id, "target_unreachable", False, "identity_mismatch")
            raise ContractError("campaign_request", f"identity_mismatch {exc}") from exc
        self._runner.identity_calls += 1

    # ordinary loop -----------------------------------------------------------------------------------------
    def _ordinary(self, correlation_id: str, mode: str | None) -> RunOutcome:
        request = request_of(require_campaign(self._conn, correlation_id))
        tried: set[str] = set()
        # A pinned request names the first category. An unpinned placeholder does not. Rank fills it once.
        # A stored current_category, including one a redirect already wrote, is not replaced.
        campaign = require_campaign(self._conn, correlation_id)
        current = campaign["current_category"]
        if not current and int(campaign["category_pinned"]) == 0:
            ranked = self.next_request(correlation_id)
            if ranked is None:
                return self._stop(correlation_id, "no_findings_in_window", False, "nothing attackable")
            current = ranked["category"]
        elif not current:
            current = request["category"]
        self._conn.execute(
            "UPDATE campaigns SET current_category = ? WHERE correlation_id = ?", (current, correlation_id)
        )
        self._conn.commit()
        while True:
            self.next_request(correlation_id)  # persists the ranking for audit, even when the request names a category
            category = str(require_campaign(self._conn, correlation_id)["current_category"])
            if category in tried:
                return self._stop(correlation_id, "no_findings_in_window", False, "nothing attackable")
            tried.add(category)
            self._conn.execute(
                "UPDATE campaigns SET current_category = ? WHERE correlation_id = ?", (category, correlation_id)
            )
            self._conn.commit()
            updated = dict(request)
            updated["category"] = category
            stopped = self._attack_until_stop(correlation_id, updated, mode)  # type: ignore[arg-type]
            if stopped is not None:
                return stopped
            decision = decide(self._conn, correlation_id, self._config.stop, float(request["per_run_usd_cap"]))
            if decision.action == "continue":
                return self._finish(correlation_id)
            if decision.action == "halt":
                return self._stop(correlation_id, "no_findings_in_window", False, decision.reason)
            ranking = next_category(
                self._conn, str(require_campaign(self._conn, correlation_id)["system_version"]),
                frozenset(c.category for c in self._seeds) - frozenset(tried),
                self._config.weights, self._config.fallback_order,
            )
            nxt = ranking.first
            if nxt is None:
                return self._stop(correlation_id, "no_findings_in_window", False, decision.reason)
            apply_redirect(self._conn, correlation_id, nxt)
            redirected = dict(request)
            redirected["category"] = nxt
            request = redirected  # type: ignore[assignment]

    def _attack_until_stop(
        self, correlation_id: str, request: CampaignRequest, mode: str | None
    ) -> RunOutcome | None:
        cap = min(int(request["attack_count_cap"]), self._config.limits.max_sequences_per_campaign)
        blocked: set[str] = set()
        while int(require_campaign(self._conn, correlation_id)["sequences_started"]) < cap:
            decision = decide(self._conn, correlation_id, self._config.stop, float(request["per_run_usd_cap"]))
            if decision.action != "continue":
                return None
            # Reselect after a claimed mutation so the next attack is not stuck on a used parent.
            chosen = mode if mode is not None else self._select_mode(correlation_id, request["category"], blocked)
            parent = self._eligible_parent(correlation_id, request["category"]) if chosen == "mutation" else None
            if chosen == "mutation" and parent is None:
                return None
            try:
                generated = self._generator.generate(request, chosen, parent=parent)
            except GenerationStopped as exc:
                if exc.halt is not None:
                    return self._from_halt(correlation_id, exc.halt.halt)  # GenerationStopped.halt is a StepHalt
                if mode is not None or chosen != "mutation":
                    # The campaign's own mode produced nothing. A requested multi-turn is not quietly run as one turn.
                    return None
                # A mutation produced nothing. Do not select it again for this category.
                blocked.add(chosen)
                continue
            outcome = self._execute_and_judge(correlation_id, generated)
            if outcome is not None:
                return outcome
        return None

    def _select_mode(self, correlation_id: str, category: str, blocked: set[str] | None = None) -> str:
        """Mutation for an unclaimed eligible partial. Otherwise the campaign's stored request.

        The stored request is multi_turn when the campaign asked for it, and novel (one turn) otherwise. It is read
        from the campaign row, so a resumed campaign keeps it.
        """
        if "mutation" not in (blocked or set()) and self._eligible_parent(correlation_id, category) is not None:
            return "mutation"
        requested = require_campaign(self._conn, correlation_id).get("requested_mode")
        return "multi_turn" if requested == "multi_turn" else "novel"

    def _eligible_parent(self, correlation_id: str, category: str) -> Parent | None:
        rows = self._conn.execute(
            """
            SELECT id FROM signals
            WHERE correlation_id = ? AND category = ? AND verdict = 'partial'
              AND id NOT IN (SELECT signal_id FROM mutation_claims)
            ORDER BY id
            """,
            (correlation_id, category),
        ).fetchall()
        for (signal_id,) in rows:
            try:
                return load_parent(self._conn, int(signal_id), self._config)
            except GenerationStopped:
                continue
        return None

    # one attack --------------------------------------------------------------------------------------------
    def _execute_and_judge(self, correlation_id: str, generated: Generated) -> RunOutcome | None:
        """Returns a terminal outcome, or None to keep going. A mismatch is a typed ContractError."""
        result = generated.attack
        if result["correlation_id"] != correlation_id:
            raise ContractError("attack_result", "correlation_id differs from the campaign")
        set_phase(self._conn, correlation_id, "attacking", role="harness")
        log_run(self._conn, correlation_id, "red_team", "running")
        transcript_id = f"rec-{generated.model_call_id}"[:64]
        try:
            executed = self._runner.run(correlation_id, generated.turns, transcript_id)
        except PreflightRefused as exc:
            return self._stop(correlation_id, "budget_exceeded", False, exc.reason)
        except UnknownOutcome as exc:
            return self._stop(correlation_id, "target_unreachable", True, f"unknown_outcome {exc.call_id}")
        if executed.halt is not None and executed.transcript is None:
            return self._from_halt(correlation_id, executed.halt)
        self._generator.persist(
            request_of(require_campaign(self._conn, correlation_id)), generated, claim_parent=True
        )
        bump(self._conn, correlation_id, "attacks_done")
        if executed.transcript is None:
            return None
        return self._judge(correlation_id, result, executed, generated)

    def _judge(
        self, correlation_id: str, result: AttackResult, executed: SequenceResult, generated: Generated
    ) -> RunOutcome | None:
        set_phase(self._conn, correlation_id, "judging", role="judge")
        # Bind only for this call. A stub grades with no journal row. A provider call is the journaled send.
        self._step += 1
        self._grader.bind_dispatch(self._journal, self._conn, self._config.retry, lambda: self._step, lambda _s: None)
        try:
            judged = self._grader.judge_transcript(result, executed.transcript)
        finally:
            self._grader.bind_dispatch(None, None, None, None, None)
        if isinstance(judged, dict) and judged.get("correlation_id") not in (None, correlation_id):
            raise ContractError("verdict", "correlation_id differs from the campaign")
        record_signal(
            self._conn, result, judged, executed.transcript,
            parent_id=generated.parent_signal_id, depth=generated.depth,
        )
        if _graded(judged):
            campaign = require_campaign(self._conn, correlation_id)
            coverage_from(
                self._conn,
                str(campaign["system_version"]),
                str(result["category"]),
                fail=judged.get("verdict") == "fail" or judged.get("status") == "draft",
            )
        if isinstance(judged, dict):
            self._verdicts.append(dict(judged))
        if isinstance(judged, dict) and judged.get("status") == "draft" and "exploit_id" in judged:
            self._store_exploit(correlation_id, dict(judged), result, executed.transcript)
        set_phase(self._conn, correlation_id, "recording", role="harness")
        self._accept(correlation_id, judged)
        if executed.halt is not None:
            return self._from_halt(correlation_id, executed.halt)
        if isinstance(judged, dict) and judged.get("error_code") == "judge_timeout":
            return self._stop(correlation_id, "judge_timeout", True, str(judged.get("detail", "")))
        if isinstance(judged, dict) and judged.get("error_code") == "budget_exceeded":
            return self._stop(correlation_id, "budget_exceeded", False, str(judged.get("detail", "")))
        return None

    def _store_exploit(self, correlation_id: str, judged: dict[str, Any], result: AttackResult, transcript: object) -> None:
        campaign = require_campaign(self._conn, correlation_id)
        subcategory = str(result["subcategory"])
        stored = False
        try:
            insert_exploit(
                self._conn,
                {
                    "id": judged["exploit_id"],
                    "severity": judged["severity"],
                    "category": judged["category"],
                    "reproduction_steps": judged["minimal_sequence"],
                    "observed_behavior": judged["observed_behavior"],
                    "expected_behavior": judged["expected_behavior"],
                    "system_version": campaign["system_version"],
                    "status": "draft",
                },
                issue_grant("judge"),
            )
            stored = True
        except DuplicateSequence:
            stored = False
        if not stored and self._conn.execute("SELECT 1 FROM regression_cases WHERE exploit_id = ?", (judged["exploit_id"],)).fetchone():
            return
        insert_regression_case(
            self._conn,
            grant=issue_grant("harness"),
            case_id=f"rc-{judged['exploit_id']}"[:64],
            exploit_id=str(judged["exploit_id"]),
            category=str(judged["category"]),
            subcategory=subcategory,
            invariant_id=invariant_id_for(subcategory),
            expected_safe_behavior=str(judged["expected_behavior"]),
            system_version=str(campaign["system_version"]),
        )
        canary = _CANARY.get(subcategory)
        recorded = _target_evidence(transcript)
        # Prefer the recorded target text. Fall back to the exploit evidence when the transcript has no target turn.
        evidence = recorded or str(judged.get("observed_behavior", ""))
        draft_report(
            self._conn,
            judged,  # type: ignore[arg-type]
            issue_grant("documentation"),
            held=is_false_positive(judged, evidence, canary),
        )
        self._conn.commit()

    def _replay_pending(self, correlation_id: str) -> None:
        """Claim every pending or owned handoff, in recorded order, and replay every eligible case on the stub.

        A missing stub is not a skip. The campaign halts before any case is dropped. A second pending handoff is
        not left behind. A handoff claimed by another correlation id is left alone.
        """
        rows = self._conn.execute(
            "SELECT id, status, claimed_by FROM version_handoffs WHERE status IN ('pending', 'claimed') ORDER BY id"
        ).fetchall()
        if not rows:
            return
        if self._stub is None:
            self._stop(correlation_id, "target_unreachable", False, "regression suite has no stub")
            raise ContractError("regression_detected", "regression suite has no stub")
        for row in rows:
            handoff_id, status, owner = int(row[0]), str(row[1]), row[2]
            if status == "pending":
                claimed = claim_handoff(self._conn, handoff_id, correlation_id)
                if claimed != "claimed":
                    continue
            elif owner != correlation_id:
                continue
            outcome = run_suite(
                self._conn, handoff_id, correlation_id, self._stub, reports_dir=self._reports_dir
            )
            if outcome.status == "predecessor_invalid":
                self._stop(correlation_id, "regression_detected", False, "predecessor pin is not the recorded previous pin")
                raise ContractError("regression_detected", "predecessor pin is not the recorded previous pin")
            if outcome.status == "regression_detected" and outcome.detections:
                detail = str(outcome.detections[0].get("detail", "regression_detected"))
                self._stop(correlation_id, "regression_detected", False, detail)
                raise ContractError("regression_detected", detail)

    def _accept(self, correlation_id: str, judged: Any) -> None:
        """Harness receives the verdict only. The report was drafted in _store_exploit. A no-op row is the record."""
        if isinstance(judged, dict) and "verdict" in judged and "exploit_id" not in judged:
            validate("verdict", judged)
        log_run(self._conn, correlation_id, "harness", "running")

    # variant campaign --------------------------------------------------------------------------------------
    def _variants(self, correlation_id: str, requested: int) -> RunOutcome:
        count = validate_variants(requested)
        request = request_of(require_campaign(self._conn, correlation_id))
        try:
            check_judge_drift()
        except JudgeDrift as exc:
            return self._stop(correlation_id, "no_findings_in_window", False, f"judge_drift {exc}")
        parent = self._any_partial_parent(request["category"])
        if parent is None:
            return self._stop(correlation_id, "no_findings_in_window", False, "no eligible parent")
        report = NoveltyReport(self._config.novelty_threshold)
        accepted: list[Generated] = []
        self._generator.total_rejections = 0
        while len(accepted) < count:
            if self._generator.total_rejections > self._config.variants.max_total_rejections:
                break
            try:
                generated = self._generator.generate(
                    request, "variant", parent=parent, accepted=accepted, report=report,
                    max_rejections=self._config.variants.max_total_rejections - self._generator.total_rejections,
                )
            except GenerationStopped as exc:
                if exc.kind == "rejections":
                    break
                if exc.halt is not None:
                    return self._from_halt(correlation_id, exc.halt.halt)  # GenerationStopped.halt is a StepHalt
                break
            outcome = self._execute_and_judge(correlation_id, generated)
            if outcome is not None:
                outcome.novelty = report.as_dict()
                outcome.verdicts = list(self._verdicts)
                return outcome
            self._record_accepted(report, parent, accepted, generated)
            accepted.append(generated)
        done = self._finish(correlation_id, detail=f"{len(accepted)} variants")
        done.novelty = report.as_dict()
        done.verdicts = list(self._verdicts)
        return done

    def _record_accepted(
        self, report: NoveltyReport, parent: Parent, earlier: list[Generated], generated: Generated
    ) -> None:
        """Keep every accepted comparison. check_novel drops them when a later retry reuses the candidate id.

        One parent comparison plus one comparison with each earlier accepted variant. Ten variants are 55 pairs.
        This does not accept or reject. The generator already did that.
        """
        name = generated.model_call_id or f"variant:{len(earlier) + 1}"
        report.pairs.append((name, f"parent:{parent.signal_id}", sequence_distance(generated.turns, parent.turns)))
        report.pairs.extend(
            (name, prior.model_call_id or f"variant:{index + 1}", sequence_distance(generated.turns, prior.turns))
            for index, prior in enumerate(earlier)
        )

    def _any_partial_parent(self, category: str) -> Parent | None:
        rows = self._conn.execute(
            "SELECT id FROM signals WHERE category = ? AND verdict = 'partial' ORDER BY id DESC", (category,)
        ).fetchall()
        for (signal_id,) in rows:
            try:
                return load_parent(self._conn, int(signal_id), self._config)
            except GenerationStopped:
                continue
        return None

    # endings -----------------------------------------------------------------------------------------------
    def _from_halt(self, correlation_id: str, typed: Halt) -> RunOutcome:
        return self._stop(correlation_id, str(typed.code), bool(typed.retryable), str(typed.detail))

    def _finish(self, correlation_id: str, detail: str = "") -> RunOutcome:
        set_phase(self._conn, correlation_id, "done")
        campaign = require_campaign(self._conn, correlation_id)
        return RunOutcome(correlation_id, "done", detail=detail, sequences=int(campaign["sequences_started"]))

    def _stop(self, correlation_id: str, code: str, retryable: bool, detail: str) -> RunOutcome:
        halt(self._conn, correlation_id, code, detail, retryable=retryable, role="orchestrator")
        campaign = require_campaign(self._conn, correlation_id)
        return RunOutcome(
            correlation_id, "halted", error_code=code, detail=detail, sequences=int(campaign["sequences_started"])
        )


def _target_evidence(transcript: object) -> str:
    """The recorded target text. That is the canary evidence, not the transcript id."""
    try:
        return target_text(require_transcript(transcript)) or ""
    except TranscriptRejected:
        return ""


def scripted_model(replies: Sequence[str]) -> ModelClient:
    """A test seam. Production constructs its client from the provider transport, never here."""
    from agentforge.agents.red_team_generator import ModelReply

    class _Client:
        def __init__(self) -> None:
            self._replies = list(replies)
            self.calls = 0

        def complete(self, prompt: str) -> ModelReply:
            index = min(self.calls, len(self._replies) - 1)
            self.calls += 1
            return ModelReply(self._replies[index], 0.0)

    return _Client()


def _graded(judged: Any) -> bool:
    """A verdict or a confirmed exploit. An error envelope is not coverage."""
    return isinstance(judged, dict) and "error_code" not in judged and (
        "verdict" in judged or judged.get("status") == "draft"
    )


def coverage_from(conn: sqlite3.Connection, system_version: str, category: str, *, fail: bool) -> None:
    """Add one graded result to the version row. A later campaign must not replace these counts."""
    conn.execute(
        """
        INSERT INTO coverage_metrics (category, system_version, case_count, pass_count, fail_count)
        VALUES (?, ?, 1, ?, ?)
        ON CONFLICT (category, system_version) DO UPDATE SET
            case_count = case_count + 1,
            fail_count = fail_count + excluded.fail_count,
            pass_count = (case_count + 1) - (fail_count + excluded.fail_count)
        """,
        (category, system_version, 0 if fail else 1, 1 if fail else 0),
    )
    conn.commit()
