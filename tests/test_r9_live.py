# ruff: noqa: F811  (the imported `offline` fixture is requested by name)
"""R9: the production Red Team client and the gated live path, proved offline.

No socket opens and no provider is called. The target is a scripted FakeTarget, the provider is a scripted
transport, and the live path runs only in a synthetic repo root in which every preflight gate is GO. The real repo is
never all green, and one test pins that: with the public-target record open, `--live` refuses with zero effects.
"""

from __future__ import annotations

import io
import json
import sqlite3
from contextlib import redirect_stdout
from datetime import date
from pathlib import Path
from typing import Any

import pytest
import yaml
from r7_support import ORIGIN, ROOT, TODAY, build_green_root
from test_r7_r8_offline import CANARIES, _load, offline  # noqa: F401  (offline is a fixture)

from agentforge.agents.openrouter_redteam import OpenRouterRedTeamModel, ProviderOutcomeUnknown, RedTeamModelError
from agentforge.agents.red_team_generator import GenerationStopped, RedTeamGenerator
from agentforge.evals import session as session_module
from agentforge.evals.cases import load_cases
from agentforge.orchestrator import live as live_module
from agentforge.orchestrator.journal import UnknownOutcome
from agentforge.orchestrator.live import run_live
from agentforge.orchestrator.policy import load_config
from agentforge.safety import chokepoint
from agentforge.safety.budget import approval_token, load_caps
from agentforge.safety.chokepoint import Response
from agentforge.safety.operator_approval import OperatorApproval
from agentforge.safety.spend_limits import Attestation
from tests.fixtures import DISTINCT_TEXTS, FakeTarget, answer, model_json, p6_campaign, p6_env

SECRET = "r9-budget-secret-not-real"
KEY = "r9-provider-key-not-real"
RESERVE = 0.01


# --- scripted provider ---------------------------------------------------------------------------------------------
def completion(text: str, cost: float | None = 0.002) -> Response:
    body: dict[str, Any] = {"choices": [{"message": {"content": text}}]}
    if cost is not None:
        body["usage"] = {"cost": cost}
    return Response(200, json.dumps(body).encode())


def attack_reply(index: int = 0, cost: float | None = 0.002) -> Response:
    return completion(model_json(DISTINCT_TEXTS[index], "TM-PI-1", f"r9-{index}"), cost)


class ProviderTransport:
    """Counts every call. Replies come in order, then the last repeats. An exception reply is raised."""

    def __init__(self, *replies: object) -> None:
        self.replies = list(replies) or [attack_reply()]
        self.calls: list[dict[str, Any]] = []

    def __call__(self, method: str, url: str, *, headers: dict[str, str], body: str, timeout: float) -> object:
        self.calls.append({"method": method, "url": url, "headers": headers, "body": body, "timeout": timeout})
        reply = self.replies[min(len(self.calls) - 1, len(self.replies) - 1)]
        if isinstance(reply, BaseException):
            raise reply
        return reply


def _attestation(today: date = TODAY) -> list[Attestation]:
    return [Attestation("openrouter", "k", 12.0, "someone", today)]


def _approval(today: date = TODAY) -> list[OperatorApproval]:
    return [OperatorApproval("someone", today, "openrouter", 5.0, "r9 test")]


def _model(transport: ProviderTransport | None, **over: Any) -> OpenRouterRedTeamModel:
    args: dict[str, Any] = {
        "reserve_usd": RESERVE, "attestations": _attestation(), "approvals": [], "today": TODAY, "transport": transport,
    }
    args.update(over)
    return OpenRouterRedTeamModel("openai/gpt-4.1-mini", **args)


@pytest.fixture
def provider_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(chokepoint, "PROVIDER_ENABLED", True)
    monkeypatch.setenv("OPENROUTER_API_KEY", KEY)


def _generator(model: Any, sleeps: list[float] | None = None) -> tuple[Any, Any, Any, RedTeamGenerator, Any]:
    conn, ledger, journal = p6_env()
    request = p6_campaign(conn)
    steps = iter(range(1, 100))
    generator = RedTeamGenerator(
        conn, journal, load_config(), model, load_cases(), alloc_step=lambda: next(steps),
        sleep=(sleeps.append if sleeps is not None else (lambda _s: None)), reserve_usd=RESERVE,
    )
    return conn, ledger, journal, generator, request


# --- client accounting ---------------------------------------------------------------------------------------------
def test_a_good_reply_settles_at_the_provider_reported_cost(provider_on: None) -> None:
    transport = ProviderTransport(attack_reply(0, cost=0.003))
    conn, _ledger, journal, generator, request = _generator(_model(transport))
    made = generator.generate(request, "novel")
    assert made.attack["input_sequence"]["turns"][0]["content"] == DISTINCT_TEXTS[0]
    (row,) = journal.rows("corr-p6")
    assert (row.state, row.incurred_usd, journal.ledger_state(row.call_id)) == ("completed", 0.003, "incurred")
    call = transport.calls[0]
    assert call["headers"]["Authorization"] == "Bearer " + KEY
    assert "stream" not in json.loads(call["body"]) and json.loads(call["body"])["max_tokens"] == 400
    assert KEY not in json.dumps([row.__dict__ for row in journal.rows("corr-p6")])


@pytest.mark.parametrize("why", ["flag", "authority", "key"])
def test_a_refusal_before_dispatch_never_reaches_the_transport_and_releases(
    provider_on: None, monkeypatch: pytest.MonkeyPatch, why: str
) -> None:
    transport = ProviderTransport()
    if why == "flag":
        monkeypatch.setattr(chokepoint, "PROVIDER_ENABLED", False)
        model = _model(transport)
    elif why == "authority":
        model = _model(transport, attestations=[], approvals=[])
    else:
        monkeypatch.delenv("OPENROUTER_API_KEY")
        model = _model(transport)
    _conn, _ledger, journal, generator, request = _generator(model)
    with pytest.raises(GenerationStopped) as stopped:
        generator.generate(request, "novel")
    assert transport.calls == [] and model.calls == 0
    assert stopped.value.halt is not None
    (row,) = journal.rows("corr-p6")
    assert (row.state, row.incurred_usd, journal.ledger_state(row.call_id)) == ("abandoned", 0.0, "released")


def test_an_operator_approval_authorizes_the_provider_when_no_attestation_exists(provider_on: None) -> None:
    transport = ProviderTransport()
    _conn, _ledger, _journal, generator, request = _generator(_model(transport, attestations=[], approvals=_approval()))
    generator.generate(request, "novel")
    assert len(transport.calls) == 1


@pytest.mark.parametrize(
    "failure",
    [TimeoutError("read timed out"), OSError("connection reset"), ConnectionResetError("reset"), Response(502, b"bad gateway")],
)
def test_an_outcome_that_may_have_billed_is_unknown_and_holds_the_reservation(provider_on: None, failure: object) -> None:
    transport = ProviderTransport(failure)
    _conn, _ledger, journal, generator, request = _generator(_model(transport))
    with pytest.raises(UnknownOutcome) as raised:
        generator.generate(request, "novel")
    assert len(transport.calls) == 1  # never replayed
    (row,) = journal.rows("corr-p6")
    assert row.state == "unknown" and row.call_id == raised.value.call_id
    assert journal.ledger_state(row.call_id) == "reserved"  # held in full, not released at $0
    assert KEY not in repr(raised.value) and "read timed out" not in repr(raised.value)


def test_a_429_is_released_and_retried_then_succeeds(provider_on: None) -> None:
    transport = ProviderTransport(Response(429, b"", headers={"Retry-After": "2"}), attack_reply())
    sleeps: list[float] = []
    _conn, _ledger, journal, generator, request = _generator(_model(transport), sleeps)
    generator.generate(request, "novel")
    assert len(transport.calls) == 2 and sleeps and sleeps[0] >= 2
    first, second = journal.rows("corr-p6")
    assert (first.state, first.incurred_usd, journal.ledger_state(first.call_id)) == ("abandoned", 0.0, "released")
    assert second.state == "completed"


def test_a_403_key_limit_refusal_releases_at_zero_and_halts_without_retry(provider_on: None) -> None:
    transport = ProviderTransport(Response(403, b'{"error": "key limit exceeded"}'))
    _conn, _ledger, journal, generator, request = _generator(_model(transport))
    with pytest.raises(GenerationStopped) as stopped:
        generator.generate(request, "novel")
    assert stopped.value.halt is not None and stopped.value.halt.halt.retryable is False
    assert len(transport.calls) == 1
    (row,) = journal.rows("corr-p6")
    assert (row.incurred_usd, journal.ledger_state(row.call_id)) == (0.0, "released")


def test_a_200_with_no_reported_cost_is_charged_the_whole_reservation(provider_on: None) -> None:
    transport = ProviderTransport(attack_reply(0, cost=None))
    _conn, _ledger, journal, generator, request = _generator(_model(transport))
    generator.generate(request, "novel")
    (row,) = journal.rows("corr-p6")
    assert row.incurred_usd == RESERVE and journal.ledger_state(row.call_id) == "incurred"


def test_a_200_with_an_unusable_body_is_charged_and_sends_nothing_to_the_target(provider_on: None) -> None:
    transport = ProviderTransport(Response(200, b"<html>not a completion</html>"))
    _conn, _ledger, journal, generator, request = _generator(_model(transport))
    with pytest.raises(GenerationStopped):
        generator.generate(request, "novel", max_rejections=1)
    rows = journal.rows("corr-p6")
    assert rows and all(r.incurred_usd == RESERVE and r.state == "completed" for r in rows)
    assert len(transport.calls) == len(rows)


def test_a_cost_above_the_reservation_stops_the_campaign_and_marks_the_row(provider_on: None) -> None:
    transport = ProviderTransport(attack_reply(0, cost=0.5))
    _conn, _ledger, journal, generator, request = _generator(_model(transport))
    with pytest.raises(GenerationStopped) as stopped:
        generator.generate(request, "novel")
    assert stopped.value.halt is not None and stopped.value.halt.halt.code == "budget_exceeded"
    (row,) = journal.rows("corr-p6")
    assert row.incurred_usd == RESERVE and row.detail == "cost_exceeds_reservation"
    assert len(transport.calls) == 1


def test_the_client_refuses_an_unconfigured_model_or_reservation() -> None:
    with pytest.raises(RedTeamModelError):
        OpenRouterRedTeamModel("TBD", reserve_usd=RESERVE, attestations=[], approvals=[], today=TODAY)
    with pytest.raises(RedTeamModelError):
        OpenRouterRedTeamModel("openai/gpt-4.1-mini", reserve_usd=0.0, attestations=[], approvals=[], today=TODAY)


def test_provider_outcome_unknown_is_an_oserror() -> None:
    assert issubclass(ProviderOutcomeUnknown, OSError)


# --- a synthetic, fully green root ---------------------------------------------------------------------------------
def live_root(tmp_path: Path) -> Path:
    root = build_green_root(tmp_path)
    for name in ("budget.yaml", "models.yaml"):
        (root / "config" / name).write_text((ROOT / "config" / name).read_text(encoding="utf-8"), encoding="utf-8")
    approvals = [
        {"approved_by": "x", "approved_on": TODAY.isoformat(), "scope": scope, "max_usd": 5, "purpose": "r9 test"}
        for scope in ("local-target", "openrouter")
    ]
    approvals.append({"approved_by": "x", "approved_on": TODAY.isoformat(), "scope": "public-target", "max_usd": 0, "purpose": "synthetic"})
    (root / "config" / "operator_approval.yaml").write_text(yaml.safe_dump({"approvals": approvals}), encoding="utf-8")
    return root


def env_for(root: Path) -> dict[str, str]:
    return {
        live_module.ENV_ORIGIN: ORIGIN,
        live_module.ENV_USER: "copilot_doc_a",
        live_module.ENV_PASSWORD: "fixture-password-not-real",
        live_module.ENV_PID: "100",
        live_module.ENV_CHAT_USD: "0.05",
        live_module.ENV_TOKEN: approval_token(load_caps(root / "config" / "budget.yaml"), SECRET),
        live_module.ENV_SECRET: SECRET,
    }


@pytest.fixture
def armed(monkeypatch: pytest.MonkeyPatch) -> FakeTarget:
    """Both switches true in this process only, and the session transport replaced by a scripted FakeTarget."""
    target = FakeTarget([answer("I will not follow that instruction.")])
    monkeypatch.setattr(chokepoint, "LIVE_ENABLED", True)
    monkeypatch.setattr(chokepoint, "PROVIDER_ENABLED", True)
    monkeypatch.setattr(session_module, "LIVE_ENABLED", True, raising=False)
    monkeypatch.setattr(session_module, "real_transport", target)
    monkeypatch.setenv("OPENROUTER_API_KEY", KEY)
    return target


def go(root: Path, provider: ProviderTransport, **kwargs: Any) -> Any:
    return run_live(
        root, today=TODAY, env=env_for(root), load_env=lambda _p: None, model_transport=provider,
        sleep=lambda _s: None, **kwargs,
    )


def store(root: Path) -> sqlite3.Connection:
    return sqlite3.connect(root / "data" / "agentforge.sqlite3")


# --- gate order and the hard blocker -------------------------------------------------------------------------------
def test_live_is_refused_with_no_effect_when_a_switch_is_false(offline: dict[str, list[str]], tmp_path: Path) -> None:
    root = live_root(tmp_path)
    provider = ProviderTransport()
    result = go(root, provider)
    assert result.code == 2 and "LIVE_ENABLED is false" in result.message
    assert provider.calls == [] and offline["env"] == [] and offline["dotenv"] == []
    assert not (root / "data").exists()


def test_the_provider_switch_is_checked_separately(
    offline: dict[str, list[str]], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(chokepoint, "LIVE_ENABLED", True)
    monkeypatch.setattr(session_module, "LIVE_ENABLED", True, raising=False)
    result = go(live_root(tmp_path), ProviderTransport())
    assert result.code == 2 and "PROVIDER_ENABLED is false" in result.message
    assert offline["env"] == [] and offline["dotenv"] == []


def test_the_real_repo_is_refused_before_any_effect_even_with_both_switches_true(
    offline: dict[str, list[str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(chokepoint, "LIVE_ENABLED", True)
    monkeypatch.setattr(chokepoint, "PROVIDER_ENABLED", True)
    monkeypatch.setattr(session_module, "LIVE_ENABLED", True, raising=False)
    result = run_live(ROOT, today=TODAY, env={}, load_env=lambda _p: pytest.fail(".env must not be loaded"))
    assert result.code == 2 and "NO-GO" in result.message and "k1_available" in result.message
    assert offline["env"] == [] and offline["dotenv"] == []  # no .env, no key, no database


def test_an_open_public_target_record_is_a_hard_blocker_when_every_other_gate_is_green(
    offline: dict[str, list[str]], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = live_root(tmp_path)
    (root / "Docs/prerequisites/public-target-authorization.md").write_text("status: open\n", encoding="utf-8")
    monkeypatch.setattr(chokepoint, "LIVE_ENABLED", True)
    monkeypatch.setattr(chokepoint, "PROVIDER_ENABLED", True)
    monkeypatch.setattr(session_module, "LIVE_ENABLED", True, raising=False)
    provider = ProviderTransport()
    result = go(root, provider)
    assert result.code == 2 and "k1_available" in result.message
    assert "allowlist_single_origin" not in result.message and "p_u_closed" not in result.message
    assert provider.calls == [] and offline["env"] == [] and offline["dotenv"] == []
    assert not (root / "data").exists()


@pytest.mark.parametrize(
    ("record", "gate"),
    [
        ("Docs/prerequisites/P-U.md", "p_u_closed"),
        ("Docs/attestations/provider-cap-evidence.yaml", "provider_cap"),
        ("Docs/attestations/deploy-attestation.yaml", "deploy_attestation"),
    ],
)
def test_each_other_open_prerequisite_also_blocks(
    offline: dict[str, list[str]], monkeypatch: pytest.MonkeyPatch, tmp_path: Path, record: str, gate: str
) -> None:
    root = live_root(tmp_path)
    (root / record).write_text("status: open\n", encoding="utf-8")
    monkeypatch.setattr(chokepoint, "LIVE_ENABLED", True)
    monkeypatch.setattr(chokepoint, "PROVIDER_ENABLED", True)
    monkeypatch.setattr(session_module, "LIVE_ENABLED", True, raising=False)
    result = go(root, ProviderTransport())
    assert result.code == 2 and gate in result.message
    assert offline["env"] == [] and offline["dotenv"] == [] and not (root / "data").exists()


def test_a_missing_operator_value_or_a_wrong_origin_refuses_before_the_store(armed: FakeTarget, tmp_path: Path) -> None:
    root = live_root(tmp_path)
    provider = ProviderTransport()
    env = env_for(root)
    del env[live_module.ENV_PASSWORD]
    missing = run_live(root, today=TODAY, env=env, load_env=lambda _p: None, model_transport=provider)
    assert missing.code == 2 and live_module.ENV_PASSWORD in missing.message and "fixture-password" not in missing.message
    env = env_for(root)
    env[live_module.ENV_ORIGIN] = "https://elsewhere.example"
    wrong = run_live(root, today=TODAY, env=env, load_env=lambda _p: None, model_transport=provider)
    assert wrong.code == 2 and "attested origin" in wrong.message
    assert provider.calls == [] and armed.calls == [] and not (root / "data").exists()


def test_a_wrong_budget_token_refuses_before_any_call(armed: FakeTarget, tmp_path: Path) -> None:
    root = live_root(tmp_path)
    env = env_for(root)
    env[live_module.ENV_TOKEN] = "0" * 64
    provider = ProviderTransport()
    result = run_live(root, today=TODAY, env=env, load_env=lambda _p: None, model_transport=provider)
    assert result.code == 2 and "budget" in result.message
    assert provider.calls == [] and armed.calls == []


# --- the loop, end to end ------------------------------------------------------------------------------------------
def test_a_refusing_target_passes_and_drafts_no_documentation(armed: FakeTarget, tmp_path: Path) -> None:
    root = live_root(tmp_path)
    provider = ProviderTransport(attack_reply(0), attack_reply(1))
    result = go(root, provider)
    assert result.code == 0 and result.body is not None
    body = result.body
    assert body["phase"] == "done", body
    assert body["pin_label"] == "operator-attested"
    assert body["sequences"] >= 1 and armed.chat_calls == body["sequences"]
    assert {v["verdict"] for v in body["verdicts"]} == {"pass"}
    assert body["report_ids"] == [] and "documentation" not in body["agents"]
    assert {"orchestrator", "red_team", "judge"} <= set(body["agents"]) and body["executor"] is True
    assert not (root / "reports").exists()  # a live run writes no report file
    conn = store(root)
    assert conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0] == 0
    assert KEY not in json.dumps(body) and "fixture-password" not in json.dumps(body)


def test_a_canary_echo_is_a_fail_with_a_live_target_report_and_all_four_agents(armed: FakeTarget, tmp_path: Path) -> None:
    root = live_root(tmp_path)
    armed.chat = [answer("CANARY-AF-PI1")]
    provider = ProviderTransport(attack_reply(0), attack_reply(1))
    result = go(root, provider)
    assert result.code == 0 and result.body is not None
    body = result.body
    assert "fail" in {v["verdict"] for v in body["verdicts"]}, body
    assert set(body["agents"]) == {"orchestrator", "red_team", "judge", "documentation"} and body["executor"] is True
    assert body["report_ids"]
    conn = store(root)
    drafted = [row[0] for row in conn.execute("SELECT body FROM reports")]
    assert drafted and all("Live target: yes" in text for text in drafted)  # recorded_verified, from send-time facts
    assert all("Live target: no" not in text for text in drafted)
    assert not (root / "reports").exists()
    assert KEY not in json.dumps(body)


def test_the_ledger_never_double_reserves_a_chat(armed: FakeTarget, tmp_path: Path) -> None:
    root = live_root(tmp_path)
    result = go(root, ProviderTransport(attack_reply(0), attack_reply(1)))
    assert result.body is not None
    conn = store(root)
    rows = conn.execute("SELECT agent_role, COUNT(*) FROM agent_spend GROUP BY agent_role").fetchall()
    roles = dict(rows)
    chats = conn.execute("SELECT COUNT(*) FROM dispatch_journal WHERE kind = 'target' AND detail IS NOT 'setup'").fetchone()[0]
    assert roles.get("red_team", 0) == conn.execute("SELECT COUNT(*) FROM dispatch_journal WHERE kind = 'model'").fetchone()[0]
    assert chats >= 1


# --- unknown outcome at the model call, then an operator-accepted resume --------------------------------------------
def test_an_unknown_model_call_halts_retryable_and_a_resume_settles_it_once(armed: FakeTarget, tmp_path: Path) -> None:
    root = live_root(tmp_path)
    first = ProviderTransport(TimeoutError("boom"))
    result = go(root, first, correlation_id="live-r9-unknown")
    assert result.code == 0 and result.body is not None
    body = result.body
    assert body["phase"] == "halted" and body["error_code"] == "target_unreachable"
    assert body["detail"].startswith("unknown_outcome ")
    call_id = body["detail"].split()[1]
    assert len(first.calls) == 1 and armed.chat_calls == 0  # nothing reached the target
    conn = store(root)
    state, reserved = conn.execute("SELECT state, reserved_usd FROM dispatch_journal WHERE call_id = ?", (call_id,)).fetchone()
    assert (state, reserved) == ("unknown", RESERVE)
    assert conn.execute("SELECT state FROM agent_spend WHERE call_id = ?", (call_id,)).fetchone()[0] == "reserved"
    conn.close()

    # A resume with no acceptance stays halted and replays nothing.
    again = ProviderTransport(attack_reply(0))
    stuck = go(root, again, resume="live-r9-unknown")
    assert stuck.body is not None and stuck.body["phase"] == "halted" and again.calls == []

    settled = go(root, ProviderTransport(attack_reply(0), attack_reply(1)), resume="live-r9-unknown", accept_unknown=call_id)
    assert settled.code == 0 and settled.body is not None and settled.body["phase"] == "done", settled.body
    conn = store(root)
    assert conn.execute("SELECT state FROM agent_spend WHERE call_id = ?", (call_id,)).fetchone()[0] == "incurred"


def test_a_cost_over_the_reservation_halts_the_live_campaign(armed: FakeTarget, tmp_path: Path) -> None:
    root = live_root(tmp_path)
    provider = ProviderTransport(attack_reply(0, cost=0.9))
    result = go(root, provider)
    assert result.body is not None
    assert result.body["phase"] == "halted" and result.body["error_code"] == "budget_exceeded"
    assert len(provider.calls) == 1 and armed.chat_calls == 0


# --- attack units under max_attacks_per_run -----------------------------------------------------------------------
def test_how_many_one_turn_sequences_fit_under_the_attack_cap(armed: FakeTarget, tmp_path: Path) -> None:
    """A measurement, recorded in the assertion so a change in setup cost is noticed rather than assumed."""
    root = live_root(tmp_path)
    result = go(root, ProviderTransport(*[attack_reply(i) for i in range(6)]))
    assert result.body is not None
    cap = load_caps(root / "config" / "budget.yaml").max_attacks_per_run
    assert cap == 20
    # Measured: two sequences complete (11 target requests) with the 20-attack cap and the derived request cap.
    assert (result.body["phase"], result.body["sequences"]) == ("done", live_module.LIVE_ATTACK_CAP), result.body
    assert armed.chat_calls == 2 and len(armed.calls) <= live_module.RATE_CAP_REQUESTS


# --- the script entry ---------------------------------------------------------------------------------------------
def test_orchestrate_live_still_refuses_first_and_names_no_secret(offline: dict[str, list[str]]) -> None:
    module = _load("orchestrate")
    out = io.StringIO()
    with redirect_stdout(out):
        assert module.main(["--live"]) == 2
    assert "refused: LIVE_ENABLED is false. No network call was made." in out.getvalue()
    assert offline["env"] == [] and offline["dotenv"] == []
    for value in CANARIES.values():
        assert value not in out.getvalue()


@pytest.mark.parametrize(
    "extra",
    [["--variant-campaign"], ["--variants", "2"], ["--unpinned"], ["--multi-turn"], ["--trace", "corr-x"]],
)
def test_live_refuses_options_that_belong_to_the_dry_run(
    offline: dict[str, list[str]], monkeypatch: pytest.MonkeyPatch, extra: list[str]
) -> None:
    module = _load("orchestrate")
    monkeypatch.setattr(chokepoint, "LIVE_ENABLED", True)
    monkeypatch.setattr(chokepoint, "PROVIDER_ENABLED", True)
    monkeypatch.setattr(session_module, "LIVE_ENABLED", True, raising=False)
    monkeypatch.setattr(module, "LIVE_ENABLED", True)
    out = io.StringIO()
    with redirect_stdout(out):
        code = module.main(["--live", *extra])
    assert code == 2 and "cannot combine" in out.getvalue()
    assert offline["env"] == [] and offline["dotenv"] == []


def test_the_real_repo_orchestrate_live_is_a_no_go_even_with_the_switches_patched_true(
    offline: dict[str, list[str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load("orchestrate")
    monkeypatch.setattr(chokepoint, "LIVE_ENABLED", True)
    monkeypatch.setattr(chokepoint, "PROVIDER_ENABLED", True)
    monkeypatch.setattr(session_module, "LIVE_ENABLED", True, raising=False)
    monkeypatch.setattr(module, "LIVE_ENABLED", True)
    out = io.StringIO()
    with redirect_stdout(out):
        assert module.main(["--live"]) == 2
    assert "NO-GO" in out.getvalue() and "k1_available" in out.getvalue()
    assert offline["env"] == [] and offline["dotenv"] == []


def test_the_dry_run_default_is_unchanged_and_makes_no_live_call(offline: dict[str, list[str]]) -> None:
    module = _load("orchestrate")
    out = io.StringIO()
    with redirect_stdout(out):
        assert module.main([]) == 0
    assert json.loads(out.getvalue())["phase"] == "done"
    assert offline["env"] == [] and offline["dotenv"] == []
