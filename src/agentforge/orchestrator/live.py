"""The gated live path for one orchestrated campaign. Nothing here opens a socket until every gate has passed.

This assembles the same CampaignLoop the dry-run uses: a production Red Team model client, the real session client,
the deterministic Judge and the Documentation drafter. It adds no policy of its own. It checks, in this order, and
returns a refusal with zero effects at the first failure:

1. Both kill switches are true in the running process. They are source constants a human flips for a reviewed window.
2. The offline preflight gates that a live campaign depends on are GO. `flags_false` is not one of them, because it
   is the reverse of the condition checked in step 1. K1 (public-target authorization) is a hard blocker: until its
   record is closed there is no live campaign, whatever else is true.
3. A valid deploy attestation exists, its pin outcome is not a difference, and the attested origin equals the
   allowlisted origin and the operator-supplied origin. The pin handed to the loop is the manifest commit.
4. Only then the operator `.env` is read and the required values are checked. Then the persistent store is opened and
   the shared budget is approved.

One campaign is opened: category TM-PI, surface chat, pinned, one turn, two attacks. Reports are written to the store
only. No file under `reports/` is created, so nothing here can become a published finding.

This module never sets either kill switch, never reads the provider key (the client does, at call time) and never
prints a prompt, a reply, a password, a cookie or a key. It prints ids, roles, states and counts.
"""

from __future__ import annotations

import os
import sqlite3
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from agentforge.agents.judge import RulesJudge, StubJudgeModel
from agentforge.agents.openrouter_redteam import OpenRouterRedTeamModel, RedTeamModelError
from agentforge.agents.red_team_generator import RedTeamGenerator
from agentforge.contracts.validate import validate
from agentforge.evals import session as session_module
from agentforge.evals.cases import load_cases
from agentforge.evals.session import SessionClient
from agentforge.gates.attestation import load_and_validate
from agentforge.gates.common import load_mapping
from agentforge.gates.pin import DIFFERENCE, load_manifest
from agentforge.gates.preflight import DEPLOY_ATTESTATION, GateResult, run_preflight
from agentforge.local_env import load_local_env
from agentforge.models_config import ModelsConfigError, load_models
from agentforge.orchestrator.journal import Journal, UnknownOutcome
from agentforge.orchestrator.loop import CampaignLoop, RunOutcome
from agentforge.orchestrator.policy import ConfigError, load_config
from agentforge.orchestrator.sequence import SETUP_REQUESTS, SequenceRunner
from agentforge.orchestrator.state import get_campaign, open_campaign
from agentforge.orchestrator.trace import reconstruct, trace_agents
from agentforge.safety import chokepoint
from agentforge.safety.allowlist import Allowlist
from agentforge.safety.budget import BudgetError, NotApproved, load_caps
from agentforge.safety.ledger import Ledger, load_shared_budget
from agentforge.safety.operator_approval import load_approvals
from agentforge.safety.rate import RateCap
from agentforge.safety.refusal_log import RefusalLog
from agentforge.safety.spend_limits import load_attestations
from agentforge.store.migrate import migrate

# The preflight gates a live campaign needs. flags_false is deliberately absent: it is the reverse of step 1.
REQUIRED_GATES = (
    "allowlist_single_origin",
    "deploy_attestation",
    "pin_outcome",
    "provider_cap",
    "p_u_closed",
    "lifetime_ceiling",
    "k1_available",
    "public_target_approval",
)

LIVE_CATEGORY = "TM-PI"
LIVE_SURFACE = "chat"
LIVE_ATTACK_CAP = 2
LIVE_RUN_CAP_USD = 1.0
CHAT_RESERVE_MAX_USD = 0.25
REDTEAM_RESERVE_USD = 0.01
# An upper bound on what one campaign can reserve, used only to size the lifetime-ceiling check.
MAX_REQUEST_USD = Decimal(LIVE_ATTACK_CAP) * (Decimal("0.25") + Decimal("0.01"))
DRY_RUN_DEFAULT_ID = "corr-dry"
# A run-total request cap, sized from the sequence preflight bound: setup plus one turn per sequence, plus one identity
# check on a resume. It is derived, not a tuned constant, and a campaign cannot send more than this many requests.
RATE_CAP_REQUESTS = LIVE_ATTACK_CAP * (SETUP_REQUESTS + 1) + 1

ENV_ORIGIN = "AGENTFORGE_TARGET_ORIGIN"
ENV_USER = "AGENTFORGE_FIXTURE_USER"
ENV_PASSWORD = "AGENTFORGE_FIXTURE_PASSWORD"
ENV_PID = "AGENTFORGE_FIXTURE_PID"
ENV_CHAT_USD = "AGENTFORGE_CHAT_RESERVE_USD"
ENV_TOKEN = "AGENTFORGE_BUDGET_TOKEN"
ENV_SECRET = "AGENTFORGE_BUDGET_SECRET"
REQUIRED_ENV = (ENV_ORIGIN, ENV_USER, ENV_PASSWORD, ENV_PID, ENV_CHAT_USD, ENV_TOKEN, ENV_SECRET)

STORE = Path("data") / "agentforge.sqlite3"


@dataclass(frozen=True)
class LiveResult:
    code: int
    message: str
    body: dict[str, Any] | None = None


def _refused(reason: str) -> LiveResult:
    return LiveResult(2, f"refused: {reason}")


def _flag_refusal() -> LiveResult | None:
    """Both switches must be true in this process. The first refusal text is the one the dry-run has always printed."""
    # The session module binds its own copy of the switch at import, so both copies must be true.
    if not (chokepoint.LIVE_ENABLED and getattr(session_module, "LIVE_ENABLED", False)):
        return _refused("LIVE_ENABLED is false. No network call was made.")
    if not chokepoint.PROVIDER_ENABLED:
        return _refused("PROVIDER_ENABLED is false. No network call was made.")
    return None


def _gate_refusal(results: list[GateResult]) -> LiveResult | None:
    by_name = {result.name: result for result in results}
    failed = [
        f"{name}: {by_name[name].reason}" if name in by_name else f"{name}: not reported"
        for name in REQUIRED_GATES
        if name not in by_name or not by_name[name].go
    ]
    if failed:
        return _refused("preflight is NO-GO (" + "; ".join(failed) + "). No network call was made.")
    return None


def refusal_before_effects(root: Path, *, today: date) -> LiveResult | None:
    """Steps 1 and 2. Reads local files only. No `.env`, no store, no key, no socket."""
    refusal = _flag_refusal()
    if refusal is not None:
        return refusal
    return _gate_refusal(run_preflight(root, today=today, request_usd=MAX_REQUEST_USD))


def _alloc(conn: sqlite3.Connection, correlation_id: str) -> Callable[[], int]:
    """Red Team step numbers continue from the highest ordinary step already journaled, so a resume never reuses one."""
    row = conn.execute(
        "SELECT COALESCE(MAX(step_no), 0) FROM dispatch_journal WHERE correlation_id = ? AND step_no < 1000",
        (correlation_id,),
    ).fetchone()
    state = {"next": int(row[0]) + 1}

    def alloc() -> int:
        value = state["next"]
        state["next"] += 1
        return value

    return alloc


def _verdict_label(judged: Mapping[str, Any]) -> str:
    """The Judge's label only. A confirmed exploit is a draft record with no verdict key, which is a fail."""
    if "verdict" in judged:
        return str(judged["verdict"])
    return "fail" if judged.get("status") == "draft" else "unknown"


def _summary(conn: sqlite3.Connection, outcome: RunOutcome, *, pin_label: str) -> dict[str, Any]:
    agents = trace_agents(conn, outcome.correlation_id)
    events = reconstruct(conn, outcome.correlation_id)
    return {
        "correlation_id": outcome.correlation_id,
        "phase": outcome.phase,
        "error_code": outcome.error_code,
        "detail": outcome.detail,
        "sequences": outcome.sequences,
        "verdicts": [{"verdict": _verdict_label(v)} for v in outcome.verdicts],
        "pin_label": pin_label,
        "agents": list(agents["agents"]),
        "executor": agents["executor"],
        "report_ids": agents["report_ids"],
        "gaps": events.get("gaps", []),
        "provenance": "recorded_verified is computed from send-time facts when a report is drafted; none is inferred here",
    }


def run_live(
    root: Path,
    *,
    today: date,
    env: Mapping[str, str] | None = None,
    load_env: Callable[[Path], None] = load_local_env,
    model_transport: Callable[..., object] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    resume: str | None = None,
    accept_unknown: str | None = None,
    correlation_id: str | None = None,
) -> LiveResult:
    refusal = refusal_before_effects(root, today=today)
    if refusal is not None:
        return refusal

    manifest, _problems = load_manifest(root / "config" / "target_pin.yaml")
    if manifest is None:
        return _refused("the target pin manifest is unusable")
    attestation = load_and_validate(root / DEPLOY_ATTESTATION, manifest)
    if not attestation.valid or attestation.pin is None or attestation.pin.outcome == DIFFERENCE:
        return _refused("the deploy attestation is not valid for this pin")
    record = load_mapping(root / DEPLOY_ATTESTATION) or {}
    attested_origin = str(record.get("origin", "")).rstrip("/")
    pin = manifest.commit[:7]
    pin_label = "operator-attested"

    allowlist = Allowlist.from_file(root / "config" / "allowlist.yaml")
    if not allowlist.check(attested_origin + "/interface/main/tabs/main.php").allowed:
        return _refused("the attested origin is not on the allowlist")

    try:
        models = load_models(root / "config" / "models.yaml")
    except (ModelsConfigError, OSError, ValueError):
        return _refused("the models config is unusable")
    red_team = models["red_team"]
    if red_team.provider != "openrouter" or red_team.model.upper() == "TBD":
        return _refused("the red_team model is not a configured OpenRouter model")

    # Only now may the operator environment be read.
    load_env(root / ".env")
    values = os.environ if env is None else env
    missing = [name for name in REQUIRED_ENV if not values.get(name, "")]
    if missing:
        return _refused("missing operator value for " + ", ".join(missing))
    origin = values[ENV_ORIGIN].rstrip("/")
    if origin != attested_origin:
        return _refused("the operator origin differs from the attested origin")
    pid = values[ENV_PID]
    if not pid.isdigit() or int(pid) <= 0:
        return _refused("operator fixture pid is missing")
    try:
        chat_reserve = float(values[ENV_CHAT_USD])
    except ValueError:
        return _refused("the chat reservation is not a number")
    if not 0 < chat_reserve <= CHAT_RESERVE_MAX_USD:
        return _refused("the chat reservation must be positive and at most 0.25")

    approvals = load_approvals(root / "config" / "operator_approval.yaml")
    attestations = load_attestations(root / "config" / "spend_limits.yaml")
    # Spend authority is checked where the money moves: the session client for the target and the Red Team
    # client for the provider, each accepting an attestation or a fresh $5 operator approval. Not duplicated here.
    store = root / STORE
    store.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(store)
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        migrate(conn)
        try:
            budget = load_shared_budget(conn, load_caps(root / "config" / "budget.yaml"), values[ENV_TOKEN], values[ENV_SECRET])
        except (NotApproved, BudgetError) as exc:
            return _refused(f"the shared budget was not approved ({type(exc).__name__})")
        ledger = Ledger(conn, budget)
        journal = Journal(conn, ledger)
        try:
            config = load_config()
            seeds = load_cases()
            model = OpenRouterRedTeamModel(
                red_team.model,
                reserve_usd=REDTEAM_RESERVE_USD,
                attestations=attestations,
                approvals=approvals,
                today=today,
                transport=model_transport,
            )
        except (ConfigError, RedTeamModelError, ValueError) as exc:
            return _refused(f"the live assembly is unusable ({type(exc).__name__})")

        # The loop's journal owns the ledger. The client carries none, so a chat is not reserved twice.
        client = SessionClient(
            origin,
            transport=session_module.real_transport,
            allowlist=allowlist,
            budget=budget,
            attestations=attestations,
            approvals=approvals,
            today=today,
            rate_cap=RateCap(RATE_CAP_REQUESTS),
            refusal_log=RefusalLog(root / "evals" / "results" / "refusals.log"),
            chat_reserve_usd=chat_reserve,
            fake_transport=False,
            fixture_username=values[ENV_USER],
            fixture_password=values[ENV_PASSWORD],
        )
        runner = SequenceRunner(
            conn, journal, config, client, None, pid, sleep=sleep,
            request_cap=LIVE_ATTACK_CAP, chat_reserve_usd=chat_reserve,
        )
        canaries = {case.subcategory: case.canary for case in seeds if case.category == LIVE_CATEGORY and case.canary}
        judge = RulesJudge(
            str(root / "config" / "models.yaml"), ledger, stub=StubJudgeModel(), canaries=canaries, fixture_only=True
        )

        if resume is not None:
            if get_campaign(conn, resume) is None:
                return _refused("no such campaign")
            cid = resume
        else:
            cid = correlation_id if correlation_id and correlation_id != DRY_RUN_DEFAULT_ID else "live-" + uuid.uuid4().hex[:12]
            request = {
                "message_id": "m-" + cid,
                "correlation_id": cid,
                "schema_version": "v1",
                "produced_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "target_pin": pin,
                "category": LIVE_CATEGORY,
                "surface": LIVE_SURFACE,
                "per_run_usd_cap": LIVE_RUN_CAP_USD,
                "attack_count_cap": LIVE_ATTACK_CAP,
                "approval_token_ref": "operator-approval",
            }
            validate("campaign_request", request)
            open_campaign(conn, request, system_version=pin, category_pinned=True)  # type: ignore[arg-type]

        generator = RedTeamGenerator(
            conn, journal, config, model, seeds,
            alloc_step=_alloc(conn, cid), sleep=sleep, reserve_usd=REDTEAM_RESERVE_USD,
        )
        loop = CampaignLoop(
            conn, journal, config, generator, runner, judge, seeds,
            observed_pin=pin, reports_dir=None,
        )
        try:
            outcome = loop.resume(cid, accept_unknown=accept_unknown) if resume is not None else loop.run(cid)
        except UnknownOutcome as exc:
            return LiveResult(2, f"halted: unknown outcome {exc.call_id}; nothing was replayed")
        return LiveResult(0, "ok", _summary(conn, outcome, pin_label=pin_label))
    finally:
        conn.close()


LIVE_ONLY_CONFLICTS = ("variant_campaign", "variants", "unpinned", "multi_turn", "trace")


def main_live(
    root: Path,
    *,
    conflicts: Mapping[str, bool],
    today: date | None = None,
    **kwargs: Any,
) -> LiveResult:
    """The entry the script calls. Flag refusal first, then incompatible options, then the run. No work before either."""
    refusal = _flag_refusal()
    if refusal is not None:
        return refusal
    used = [name for name in LIVE_ONLY_CONFLICTS if conflicts.get(name)]
    if used:
        return _refused(
            "--live runs one pinned, novel, one-turn campaign. It cannot combine with "
            + ", ".join("--" + name.replace("_", "-") for name in used)
            + ". No network call was made."
        )
    return run_live(root, today=today or date.today(), **kwargs)
