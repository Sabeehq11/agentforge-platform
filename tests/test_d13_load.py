"""Offline D-13 harness. No socket, no cap edit, no safety-switch change."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
import sqlite3
import subprocess
import sys
from datetime import date
from pathlib import Path

import pytest

from agentforge.evals.loadtest import (
    _require_store,
    CASES,
    _APPROVED_REVISION_FILES,
    _BASELINE_REVISION_FILES,
    _ISOLATED_REVISION_FILES,
    _REQUIRED_REVISION_FILES,
    _WEEK1_REVISION_FILES,
    LoadReport,
    LoadTestRefused,
    _require_stub_guard,
    bottleneck_from,
    _deployed_pin_matches,
    _pace,
    execute,
    latency_line,
    offline_preflight,
    probe_one_chat,
    REPORT_FILE,
    report_destination,
    report_json,
    report_problems,
    write_report,
    rate_cap_for,
    run_load,
    synthetic_cases,
)
from agentforge.evals.session import SessionClient, SessionError, real_transport, stub_ready
from agentforge.safety.allowlist import Allowlist, Entry
from agentforge.safety.budget import Budget, Caps, approval_token
from agentforge.safety.budget import load_caps
from agentforge.safety.chokepoint import LIVE_ENABLED, PROVIDER_ENABLED
from agentforge.safety.operator_approval import OperatorApproval
from agentforge.safety.rate import RateCap
from agentforge.safety.spend_limits import Attestation
from agentforge.store.migrate import migrate
from tests.fixtures import FakeTarget, answer

ROOT = Path(__file__).resolve().parents[1]
SECRET = "d13-test-secret"
TODAY = date(2026, 10, 20)
PIN = "9f03654"


@pytest.fixture(autouse=True)
def _reviewed_revision_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default git stubs name reviewed paths. Their bytes must hash to the pinned digests."""
    pinned = {digest.encode(): digest for _path, digest in _APPROVED_REVISION_FILES}
    real = hashlib.sha256

    def read_bytes(self: Path) -> bytes:
        text = str(self)
        for path, digest in _APPROVED_REVISION_FILES:
            if text.endswith(path):
                return digest.encode()
        raise FileNotFoundError(text)

    def sha256(body: bytes = b"", *args: object, **kwargs: object) -> object:
        if body in pinned:
            class Digest:
                def hexdigest(self) -> str:
                    return pinned[body]

            return Digest()
        return real(body, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    monkeypatch.setattr("agentforge.evals.loadtest.hashlib.sha256", sha256)
STUB_READY = json.dumps(
    {"status": "ready", "checks": {"llm_provider": {"ok": True, "detail": "stub provider (no network)"}}}
).encode()
STUB_GUARD = json.dumps({"stub_only": True, "accepted": True, "route": "week1-stub"}).encode()
CLAUDE_READY = json.dumps(
    {"status": "ready", "checks": {"llm_provider": {"ok": True, "detail": "HTTP 200"}}}
).encode()


def _budget(max_attacks: int) -> Budget:
    caps = Caps(5.0, 5.0, max_attacks, 5.0, 15.0)
    budget = Budget(caps)
    budget.approve(approval_token(caps, SECRET), SECRET)
    return budget


def _target(
    chat: list[tuple[int, bytes, dict[str, str] | None]],
    *,
    ready: bytes = STUB_READY,
    pin: str = PIN,
    preflight_status: int = 200,
    preflight_body: bytes | None = STUB_GUARD,
    preflight_error: BaseException | None = None,
    login_redirect: bool = False,
    dock_endpoint: str = "/interface/modules/custom_modules/oe-module-copilot/public/chat.php",
) -> FakeTarget:
    return FakeTarget(
        chat,
        pin=pin,
        ready_body=ready,
        preflight_status=preflight_status,
        preflight_body=preflight_body,
        preflight_error=preflight_error,
        login_redirect=login_redirect,
        dock_endpoint=dock_endpoint,
    )


def _run(
    client: SessionClient,
    conn: sqlite3.Connection,
    count: int = CASES,
    *,
    approved: int | None = CASES,
    pin: str = PIN,
    revision_dir: str | None = "reviewed-checkout",
):
    return run_load(
        client,
        conn,
        synthetic_cases(count),
        pin=pin,
        fixture_pid="100",
        approved_cases=approved,
        revision_dir=revision_dir,
    )


def _client(target: FakeTarget, budget: Budget, *, rate: int, reserve: float | None = 0.0) -> SessionClient:
    return SessionClient(
        "https://target.example",
        transport=target,
        allowlist=Allowlist((Entry("https", "target.example", 443, "/"),)),
        budget=budget,
        attestations=[Attestation("target", "target-key", 10.0, "someone", TODAY)],
        today=TODAY,
        rate_cap=RateCap(rate),
        chat_reserve_usd=reserve,
        fake_transport=True,
        approvals=[OperatorApproval("op", TODAY, "public-target", 0.0, "fixture", "https://target.example")],
        fixture_username="copilot_doc_a",
        fixture_password="not-a-secret",
    )


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys = ON")
    migrate(conn)
    return conn


def _sse(latency_ms: float, conversation: str = "conv-1") -> tuple[int, bytes, None]:
    body = (
        f"event: conversation\ndata: {json.dumps({'id': conversation})}\n\n"
        f"event: answer\ndata: {json.dumps({'text': 'refused'})}\n\n"
        f"event: latency_ms\ndata: {json.dumps({'llm_ms': latency_ms})}\n\n"
    )
    return (200, body.encode(), None)


def test_bottleneck_uses_only_complete_measured_spans() -> None:
    named, fix = bottleneck_from(
        orchestration_seconds=1.0,
        llm_seconds=0.1,
        llm_samples=2,
        cases_completed=2,
        storage_seconds=0.2,
        storage_rows=2,
    )
    assert named == "orchestration"
    assert "one authenticated session" in fix
    storage, storage_fix = bottleneck_from(
        orchestration_seconds=0.7,
        llm_seconds=0.1,
        llm_samples=2,
        cases_completed=2,
        storage_seconds=0.5,
        storage_rows=2,
    )
    assert storage == "exploit_storage"
    assert "one transaction" in storage_fix
    assert bottleneck_from(
        orchestration_seconds=0.3,
        llm_seconds=0.1,
        llm_samples=1,
        cases_completed=2,
        storage_seconds=0.1,
        storage_rows=2,
    ) == ("not_measured", "not_measured")
    assert bottleneck_from(
        orchestration_seconds=0.2,
        llm_seconds=0.1,
        llm_samples=1,
        cases_completed=1,
        storage_seconds=0.1,
        storage_rows=1,
    ) == ("not_measured", "not_measured")
    assert bottleneck_from(
        orchestration_seconds=0.1,
        llm_seconds="not_measured",
        llm_samples=0,
        cases_completed=0,
        storage_seconds=0.0,
        storage_rows=0,
    ) == ("not_measured", "not_measured")


def test_non_200_chat_does_not_count_as_completed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agentforge.evals.loadtest.subprocess.run", _Git())
    target = _target([_sse(0.0), (502, b'{"error":"agent_error"}', None)])
    report = _run(_client(target, _budget(2), rate=20), _conn(), count=2, approved=2)
    assert report.cases_completed == 1
    assert report.exploit_storage_rows == 1
    assert report.llm_latency_samples == 1
    assert report.stopped_by == "TargetStatusError"
    assert report.satisfies_d13 is False
    assert target.chats == 2


def test_pace_waits_before_the_agent_window_fills() -> None:
    from agentforge.evals.loadtest import _AGENT_CHAT_LIMIT, _AGENT_CHAT_WINDOW

    slept: list[float] = []
    stamps = [0.0] * _AGENT_CHAT_LIMIT
    _pace(stamps, sleeper=slept.append, now=lambda: 10.0)
    assert slept == [_AGENT_CHAT_WINDOW - 10.0]
    _pace(stamps, sleeper=slept.append, now=lambda: _AGENT_CHAT_WINDOW)
    assert len(slept) == 1


def test_pace_carries_all_100_chats_across_the_rolling_window() -> None:
    """Replay the live loop against the agent rule: 60 verified chats per user per rolling minute.

    _pace prunes the list it is given, so the full send log is separate. The clock advances only when
    _pace asks to sleep, so a missed wait cannot hide inside real time.
    """
    from agentforge.evals.loadtest import _AGENT_CHAT_LIMIT, _AGENT_CHAT_WINDOW

    clock = {"now": 0.0}
    chat_times: list[float] = []
    sent: list[float] = []
    slept: list[float] = []

    def sleeper(delay: float) -> None:
        assert delay > 0
        slept.append(delay)
        clock["now"] += delay

    for _case in range(CASES):
        _pace(chat_times, sleeper=sleeper, now=lambda: clock["now"])
        current = clock["now"]
        # Same comparison as the agent limiter: a hit ages out at exactly 60 seconds.
        still_open = [stamp for stamp in sent if current - stamp < _AGENT_CHAT_WINDOW]
        assert len(still_open) < _AGENT_CHAT_LIMIT
        chat_times.append(current)
        sent.append(current)

    assert len(sent) == CASES
    # Instant chats fill 59, wait out the window, then send the remaining 41. One wait covers all 100.
    assert slept == [_AGENT_CHAT_WINDOW]
    assert sent[:_AGENT_CHAT_LIMIT] == [0.0] * _AGENT_CHAT_LIMIT
    assert sent[_AGENT_CHAT_LIMIT:] == [_AGENT_CHAT_WINDOW] * (CASES - _AGENT_CHAT_LIMIT)
    for index, stamp in enumerate(sent):
        window = [older for older in sent[: index + 1] if stamp - older < _AGENT_CHAT_WINDOW]
        assert len(window) <= _AGENT_CHAT_LIMIT


def test_pace_rolls_the_window_when_chats_take_time() -> None:
    """A chat that consumes clock time must free a slot as the oldest hit ages out, not only in one batch."""
    from agentforge.evals.loadtest import _AGENT_CHAT_LIMIT, _AGENT_CHAT_WINDOW

    clock = {"now": 0.0}
    chat_times: list[float] = []
    sent: list[float] = []

    def sleeper(delay: float) -> None:
        clock["now"] += delay

    for _case in range(CASES):
        _pace(chat_times, sleeper=sleeper, now=lambda: clock["now"])
        current = clock["now"]
        assert sum(current - stamp < _AGENT_CHAT_WINDOW for stamp in sent) < _AGENT_CHAT_LIMIT
        chat_times.append(current)
        sent.append(current)
        clock["now"] += 1.0

    assert len(sent) == CASES
    assert max(sent) > _AGENT_CHAT_WINDOW
    for index, stamp in enumerate(sent):
        window = [older for older in sent[: index + 1] if stamp - older < _AGENT_CHAT_WINDOW]
        assert 0 < len(window) <= _AGENT_CHAT_LIMIT


@pytest.mark.parametrize("status", [429, 502, 503, 500, 400])
def test_failed_chat_response_never_counts_as_completed(status: int, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agentforge.evals.loadtest.subprocess.run", _Git())
    target = _target([_sse(1.0), (status, b'{"error":"agent_error"}', None), _sse(2.0)])
    report = _run(_client(target, _budget(3), rate=20), _conn(), count=3, approved=3)
    assert report.cases_completed == 1
    assert report.exploit_storage_rows == 1
    assert report.llm_latency_samples == 1
    assert report.stopped_by == "TargetStatusError"
    assert report.satisfies_d13 is False
    assert target.chats == 2


def test_load_cases_do_not_reuse_conversation_and_count_zero_latency(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agentforge.evals.loadtest.subprocess.run", _Git())
    target = _target([_sse(0.0), _sse(12.5)])
    client = _client(target, _budget(3), rate=20)
    client.session.conversation_id = "conv-carried"
    report = _run(client, _conn(), count=2, approved=2)
    sent = [json.loads(body) for body in target.chat_bodies]
    assert len(sent) == 2
    assert all("conversation_id" not in body for body in sent)
    assert client.session.conversation_id == "conv-1"
    assert report.llm_latency_samples == 2
    assert report.llm_latency_seconds == pytest.approx(0.0125)
    client.post_chat("synthetic")
    reused = json.loads(target.chat_bodies[-1])
    assert reused["conversation_id"] == "conv-1"


def test_completed_run_names_the_measured_bottleneck(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agentforge.evals.loadtest.subprocess.run", _Git())
    target = _target([_sse(0.0)])
    report = _run(_client(target, _budget(1), rate=20), _conn(), count=1, approved=1)
    body = report.as_dict()
    assert body["llm_latency_seconds"] == 0.0
    assert body["llm_latency_label"] == "target_stub_llm"
    assert body["bottleneck"] in {"orchestration", "stub_llm", "exploit_storage"}
    assert body["architectural_fix"] != "not_measured"
    assert body["satisfies_d13"] is False

    missing = _target([answer("refused")])
    incomplete = _run(_client(missing, _budget(1), rate=20), _conn(), count=1, approved=1)
    assert incomplete.as_dict()["bottleneck"] == "not_measured"
    assert incomplete.as_dict()["architectural_fix"] == "not_measured"
    assert incomplete.llm_latency_seconds == "not_measured"


def _status(files: tuple[tuple[str, str], ...]) -> str:
    return "".join(f" M {path}\n" for path, _digest in files)


def _approved_status() -> str:
    return _status(_APPROVED_REVISION_FILES)


class _Git:
    def __init__(
        self,
        head: str = "9f036541cf95e896db065e0c652afb75627b03c2",
        dirty: str | None = None,
        code: int = 0,
    ) -> None:
        if dirty is None:
            dirty = _approved_status()
        self.head = head
        self.dirty = dirty
        self.code = code
        self.calls: list[list[str]] = []

    def __call__(self, args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        self.calls.append(args)
        stdout = self.head if "rev-parse" in args else self.dirty
        return subprocess.CompletedProcess(args, self.code, stdout, "")


def test_deployed_pin_requires_d13_files_and_pins_baseline(monkeypatch: pytest.MonkeyPatch) -> None:
    assert set(dict(_REQUIRED_REVISION_FILES)) & set(dict(_BASELINE_REVISION_FILES)) == set()
    assert set(dict(_WEEK1_REVISION_FILES)) & set(dict(_ISOLATED_REVISION_FILES)) == {"agent/tests/test_chat_unit.py"}
    assert len(_APPROVED_REVISION_FILES) == (
        len(_REQUIRED_REVISION_FILES) + len(_WEEK1_REVISION_FILES) + len(_ISOLATED_REVISION_FILES) + len(_BASELINE_REVISION_FILES)
    )
    bodies = {path: digest.encode() for path, digest in _APPROVED_REVISION_FILES}

    def read(path: Path) -> bytes:
        relative = next(item for item in bodies if str(path).endswith(item))
        return bodies[relative]

    monkeypatch.setattr("agentforge.evals.loadtest.subprocess.run", _Git(dirty=_approved_status()))
    assert _deployed_pin_matches(PIN, "reviewed-checkout", reader=read) is True
    monkeypatch.setattr("agentforge.evals.loadtest.subprocess.run", _Git(dirty=_status(_REQUIRED_REVISION_FILES)))
    assert _deployed_pin_matches(PIN, "reviewed-checkout", reader=read) is True

    def reader_for(changed_path: str) -> Callable[[Path], bytes]:
        changed = dict(bodies)
        changed[changed_path] = b"changed"

        def read_changed(path: Path) -> bytes:
            relative = next(item for item in changed if str(path).endswith(item))
            return changed[relative]

        return read_changed

    monkeypatch.setattr("agentforge.evals.loadtest.subprocess.run", _Git(dirty=_approved_status()))
    assert _deployed_pin_matches(PIN, "reviewed-checkout", reader=reader_for("agent/app/chat.py")) is False
    baseline = next(path for path, _digest in _BASELINE_REVISION_FILES)
    assert _deployed_pin_matches(PIN, "reviewed-checkout", reader=reader_for(baseline)) is False
    monkeypatch.setattr(
        "agentforge.evals.loadtest.subprocess.run",
        _Git(dirty=_approved_status() + "?? unexpected/path.py\n"),
    )
    assert _deployed_pin_matches(PIN, "reviewed-checkout", reader=read) is False
    missing = _status(tuple(item for item in _WEEK1_REVISION_FILES if item[0] != "agent/app/chat.py"))
    monkeypatch.setattr("agentforge.evals.loadtest.subprocess.run", _Git(dirty=missing))
    assert _deployed_pin_matches(PIN, "reviewed-checkout", reader=read) is True
    monkeypatch.setattr("agentforge.evals.loadtest.subprocess.run", _Git(dirty=""))
    assert _deployed_pin_matches(PIN, "reviewed-checkout") is True


def test_deployed_pin_matches_only_a_reviewed_full_revision(monkeypatch: pytest.MonkeyPatch) -> None:
    git = _Git()
    monkeypatch.setattr("agentforge.evals.loadtest.subprocess.run", git)
    assert _deployed_pin_matches(PIN, "reviewed-checkout") is True
    monkeypatch.setattr("agentforge.evals.loadtest.subprocess.run", _Git(dirty=""))
    assert _deployed_pin_matches(PIN, "reviewed-checkout") is True
    monkeypatch.setattr("agentforge.evals.loadtest.subprocess.run", git)
    assert all(args[1] == "-C" and args[2] == "reviewed-checkout" for args in git.calls)
    assert _deployed_pin_matches("9f036541cf95e896db065e0c652afb75627b03c2", "reviewed-checkout") is True
    assert _deployed_pin_matches(PIN, None) is False
    assert _deployed_pin_matches("9f0365", "reviewed-checkout") is False
    monkeypatch.setattr("agentforge.evals.loadtest.subprocess.run", _Git(dirty=" M config.local.php"))
    assert _deployed_pin_matches(PIN, "reviewed-checkout") is False
    monkeypatch.setattr("agentforge.evals.loadtest.subprocess.run", _Git(head="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
    assert _deployed_pin_matches(PIN, "reviewed-checkout") is False
    monkeypatch.setattr("agentforge.evals.loadtest.subprocess.run", _Git(code=1))
    assert _deployed_pin_matches(PIN, "reviewed-checkout") is False


def test_missing_revision_refuses_before_chat(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agentforge.evals.loadtest.subprocess.run", _Git())
    target = _target([answer("refused")])
    stopped = _run(_client(target, _budget(1), rate=20), _conn(), count=1, approved=1, revision_dir=None)
    assert stopped.cases_completed == 0
    assert stopped.stopped_by == "deployed target revision does not match the pin"
    assert target.chats == 0
    assert not any(url.endswith("/ready") for _method, url in target.calls)


def test_stub_ready_accepts_only_the_no_network_detail() -> None:
    assert stub_ready(STUB_READY) is True
    assert stub_ready(CLAUDE_READY) is False
    assert stub_ready(b"not-json") is None
    assert stub_ready(STUB_GUARD) is None


def test_accept_zero_cost_stub_still_requires_a_real_ready_body() -> None:
    client = _client(_target([answer("refused")]), _budget(1), rate=20)
    with pytest.raises(SessionError, match="not a verified zero-cost stub"):
        client.accept_zero_cost_stub(b"not-json")
    assert client.zero_cost_stub is False
    with pytest.raises(SessionError, match="billable reservation"):
        _client(_target([answer("refused")]), _budget(1), rate=20, reserve=0.05).accept_zero_cost_stub(STUB_READY)
    guarded = _client(_target([answer("refused")]), _budget(1), rate=20, reserve=0.05)
    with pytest.raises(SessionError, match="billable reservation"):
        guarded.accept_authenticated_stub_guard()
    assert guarded.zero_cost_stub is False
    assert guarded.chat_reserve_usd == 0.05


def test_missing_stub_preflight_does_not_send_chat(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agentforge.evals.loadtest.subprocess.run", _Git())
    target = _target([_sse(12.5)], preflight_body=None)
    client = _client(target, _budget(100), rate=200)
    report = _run(client, _conn())
    assert report.cases_completed == 0
    assert report.stopped_by == "stub_only guard is not demonstrably active"
    assert target.chats == 0
    assert not any(url.endswith("/ready") for _method, url in target.calls)
    assert any("stub_preflight.php" in url and method == "GET" for method, url in target.calls)
    assert not any("chat.php" in url and method == "POST" for method, url in target.calls)


def test_stub_preflight_requires_exact_fields_and_reuses_session(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agentforge.evals.loadtest.subprocess.run", _Git())
    accepted = _target([answer("refused")])
    report = _run(_client(accepted, _budget(1), rate=20), _conn(), count=1, approved=1)
    assert report.cases_completed == 1
    assert report.stopped_by is None
    assert not any(url.endswith("/ready") for _method, url in accepted.calls)
    preflight = [
        (method, url, headers)
        for (method, url), headers in zip(accepted.calls, accepted.headers, strict=True)
        if "stub_preflight.php" in url
    ]
    assert preflight == [("GET", "https://target.example/interface/modules/custom_modules/oe-module-copilot/public/stub_preflight.php", {
        "Cookie": "OpenEMR=fixture-session",
        "X-CSRF-Token": "fixture-csrf",
    })]
    chat_at = next(i for i, (method, url) in enumerate(accepted.calls) if method == "POST" and "chat.php" in url)
    assert accepted.calls.index(preflight[0][:2]) < chat_at

    rejects = [
        (503, json.dumps({"error": "route_not_stub"}).encode()),
        (200, json.dumps({"stub_only": 1, "accepted": True, "route": "week1-stub"}).encode()),
        (200, json.dumps({"stub_only": "true", "accepted": True, "route": "week1-stub"}).encode()),
        (200, json.dumps({"stub_only": True, "accepted": True, "route": "week1-claude"}).encode()),
        (200, json.dumps({"stub_only": True, "accepted": True, "route": "week1-stub", "url": "http://agent:8400"}).encode()),
        (200, b"not-json"),
        (401, STUB_GUARD),
    ]
    for status, body in rejects:
        target = _target([answer("refused")], preflight_status=status, preflight_body=body)
        report = _run(_client(target, _budget(100), rate=20), _conn())
        assert report.cases_completed == 0
        assert report.stopped_by == "stub_only guard is not demonstrably active"
        assert target.chats == 0

    unsigned = _client(_target([answer("refused")]), _budget(20), rate=20)
    with pytest.raises(LoadTestRefused, match="no authenticated session"):
        _require_stub_guard(unsigned)
    assert unsigned.session.cookie is None
    assert not any("stub_preflight.php" in url for _method, url in unsigned.transport.calls)  # type: ignore[attr-defined]

    broken = _target([answer("refused")], preflight_error=OSError(61, "connection refused"))
    report = _run(_client(broken, _budget(100), rate=20), _conn())
    assert report.cases_completed == 0
    assert report.stopped_by == "stub guard preflight failed"
    assert broken.chats == 0


def _isolated_client(target: FakeTarget) -> SessionClient:
    client = SessionClient(
        "https://127.0.0.1:19300",
        transport=target,
        allowlist=Allowlist((Entry("https", "127.0.0.1", 19300, "/"),)),
        budget=_budget(1),
        attestations=[Attestation("target", "target-key", 10.0, "someone", TODAY)],
        today=TODAY,
        rate_cap=RateCap(20),
        chat_reserve_usd=0.0,
        fake_transport=True,
        fixture_username="copilot_doc_a",
        fixture_password="not-a-secret",
    )
    return client


def test_isolated_stub_without_latency_event_records_not_measured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agentforge.evals.loadtest.subprocess.run", _Git(dirty=""))
    target = _target([answer("refused")])
    client = _isolated_client(target)
    monkeypatch.setattr("agentforge.evals.loadtest._read_isolated_ready", lambda: (200, STUB_READY))
    report = _run(client, _conn(), count=1, approved=1)
    assert report.cases_completed == 1
    assert report.llm_event_absent is True
    assert report.llm_latency_seconds == "not_measured"
    assert report.llm_latency_samples == 0
    assert report.as_dict()["llm_latency_label"] == "not_measured"
    assert "stub_llm_latency" not in report_problems(report)
    assert report.bottleneck in {"orchestration", "exploit_storage"}
    public = _run(_client(_target([answer("refused")]), _budget(1), rate=20), _conn(), count=1, approved=1)
    assert public.llm_event_absent is False
    assert "stub_llm_latency" in report_problems(public)


def test_isolated_ready_accepts_only_the_stub_and_sends_no_module_request(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agentforge.evals.loadtest.subprocess.run", _Git(dirty=""))
    target = _target([answer("refused")])
    client = _isolated_client(target)
    monkeypatch.setattr("agentforge.evals.loadtest._read_isolated_ready", lambda: (200, STUB_READY))
    report = _run(client, _conn(), count=1, approved=1)
    assert report.stopped_by is None
    assert report.cases_completed == 1
    assert report.zero_cost_stub is True
    assert not any("stub_preflight.php" in url for _method, url in target.calls)
    openrouter = _target([answer("refused")])
    refused = _isolated_client(openrouter)
    monkeypatch.setattr("agentforge.evals.loadtest._read_isolated_ready", lambda: (200, CLAUDE_READY))
    stopped = _run(refused, _conn(), count=1, approved=1)
    assert stopped.cases_completed == 0
    assert stopped.stopped_by == "stub_only guard is not demonstrably active"
    assert openrouter.chats == 0


def test_ready_looking_body_does_not_replace_stub_preflight(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agentforge.evals.loadtest.subprocess.run", _Git())
    target = _target([answer("refused")], ready=STUB_READY, preflight_body=None)
    client = _client(target, _budget(100), rate=20)
    report = _run(client, _conn())
    assert report.cases_completed == 0
    assert report.stopped_by == "stub_only guard is not demonstrably active"
    assert client.zero_cost_stub is False
    assert target.chats == 0
    assert not any(url.endswith("/ready") for _method, url in target.calls)


def test_positive_reservation_cannot_be_marked_zero_cost(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agentforge.evals.loadtest.subprocess.run", _Git())
    target = _target([answer("refused")])
    client = _client(target, _budget(100), rate=20, reserve=0.05)
    report = _run(client, _conn())
    assert report.cases_completed == 0
    assert report.stopped_by == "verified stub chat cannot carry a billable reservation"
    assert client.zero_cost_stub is False
    assert target.chats == 0


def _paths(target: FakeTarget) -> list[str]:
    return [url.split("?", 1)[0] for _method, url in target.calls]


def test_protected_dock_is_fetched_only_after_login(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agentforge.evals.loadtest.subprocess.run", _Git())
    direct = _target([answer("refused")])
    report = _run(_client(direct, _budget(1), rate=20), _conn(), count=1, approved=1)
    assert report.stopped_by is None
    paths = _paths(direct)
    login = next(i for i, url in enumerate(direct.calls) if "main_screen.php" in url[1])
    dock = [i for i, path in enumerate(paths) if path.endswith("/interface/main/tabs/main.php")]
    guard = next(i for i, path in enumerate(paths) if path.endswith("stub_preflight.php"))
    assert dock and login < dock[0] < guard
    assert not any(i < login and path.endswith("/tabs/main.php") for i, path in enumerate(paths))

    redirected = _target([answer("refused")], login_redirect=True)
    followed = _run(_client(redirected, _budget(1), rate=20), _conn(), count=1, approved=1)
    assert followed.stopped_by is None
    followed_paths = _paths(redirected)
    post = next(i for i, url in enumerate(redirected.calls) if "main_screen.php" in url[1])
    hop = next(i for i, url in enumerate(redirected.calls) if "token_main=once" in url[1])
    assert hop == post + 1
    assert "Cookie" in (redirected.headers[hop] or {})
    assert not any("tabs/main.php?site=" in url for _method, url in redirected.calls)
    assert hop < next(i for i, path in enumerate(followed_paths) if path.endswith("stub_preflight.php"))

    wrong = _target([answer("refused")], dock_endpoint="/interface/modules/custom_modules/oe-module-copilot/public/other.php")
    refused = _run(_client(wrong, _budget(1), rate=20), _conn(), count=1, approved=1)
    assert refused.cases_completed == 0
    assert refused.stopped_by == "OpenEMR dock has no public chat endpoint"
    assert wrong.chats == 0
    assert any("main_screen.php" in url for _method, url in wrong.calls)


def test_rate_cap_covers_setup_and_every_chat(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agentforge.evals.loadtest.subprocess.run", _Git())
    assert rate_cap_for(1) > 1
    target = _target([_sse(0.0)])
    report = _run(_client(target, _budget(CASES), rate=rate_cap_for(CASES)), _conn())
    assert report.cases_completed == CASES
    assert report.stopped_by is None
    assert target.chats == CASES
    assert len(target.calls) == rate_cap_for(CASES)
    redirected = _target([_sse(0.0)], login_redirect=True)
    followed = _run(_client(redirected, _budget(CASES), rate=rate_cap_for(CASES)), _conn())
    assert followed.cases_completed == CASES
    assert len(redirected.calls) == rate_cap_for(CASES)
    short = _target([_sse(0.0)])
    stopped = _run(_client(short, _budget(CASES), rate=rate_cap_for(CASES) - 1), _conn())
    assert stopped.cases_completed == CASES - 1
    assert stopped.stopped_by == "refused by rate"
    assert short.chats == CASES - 1


def test_one_chat_probe_prints_numeric_latency_including_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    """The source switch stays false. fake_transport is the existing offline seam, not a live bypass."""
    monkeypatch.setattr("agentforge.evals.loadtest.subprocess.run", _Git())
    monkeypatch.setattr("agentforge.evals.loadtest.LIVE_ENABLED", True)
    zero = _target([_sse(0.0)])
    monkeypatch.setattr("agentforge.evals.loadtest.real_transport", zero)
    client = _client(zero, _budget(1), rate=rate_cap_for(1))
    line = probe_one_chat(client, pin=PIN, fixture_pid="100", revision_dir="reviewed-checkout")
    assert line == "latency_ms=0.00"
    assert client.last_llm_latency_s == 0.0
    assert zero.chats == 1
    assert client.budget.attacks == 1
    missing = _target([answer("refused")])
    monkeypatch.setattr("agentforge.evals.loadtest.real_transport", missing)
    missing_client = _client(missing, _budget(1), rate=rate_cap_for(1))
    assert probe_one_chat(missing_client, pin=PIN, fixture_pid="100", revision_dir="reviewed-checkout") == "latency_ms=missing"
    assert latency_line(type("Turn", (), {"llm_latency_ms": True})()) == "latency_ms=missing"
    monkeypatch.undo()
    monkeypatch.setattr("agentforge.evals.loadtest.subprocess.run", _Git())
    blocked = _target([_sse(1.0)])
    blocked_client = _client(blocked, _budget(1), rate=rate_cap_for(1))
    blocked_client.fake_transport = False
    blocked_client.transport = real_transport
    with pytest.raises(LoadTestRefused, match="LIVE_ENABLED"):
        probe_one_chat(blocked_client, pin=PIN, fixture_pid="100", revision_dir="reviewed-checkout")
    assert blocked.chats == 0
    live = _client(_target([_sse(1.0)]), _budget(1), rate=rate_cap_for(1))
    live.fake_transport = False
    with pytest.raises(LoadTestRefused, match="fake transport"):
        probe_one_chat(live, pin=PIN, fixture_pid="100", revision_dir="reviewed-checkout")
    assert LIVE_ENABLED is False
    assert PROVIDER_ENABLED is False


def test_cli_approval_does_not_read_provider_switch(monkeypatch: pytest.MonkeyPatch) -> None:
    sys.path.insert(0, str(ROOT))
    import scripts.loadtest as cli

    argv = ["--live", "--cases", "100", "--origin", "https://target.example", "--pin", PIN, "--pid", "100", "--revision-dir", "reviewed-checkout"]
    assert LIVE_ENABLED is False
    assert PROVIDER_ENABLED is False
    assert cli.refusal(argv, live_enabled=False) == "D-13 has no enabled live path"
    assert cli.refusal(argv, live_enabled=True) is None
    assert cli.refusal(["--cases", "100", "--origin", "https://target.example", "--pin", PIN, "--pid", "100"], live_enabled=True)
    assert cli.refusal(["--live", "--cases", "20", "--origin", "https://target.example", "--pin", PIN, "--pid", "100"], live_enabled=True)
    assert cli.refusal(
        ["--live", "--cases", "100", "--origin", "https://target.example", "--pin", PIN, "--pid", "100"],
        live_enabled=True,
    )
    monkeypatch.setattr(cli, "LIVE_ENABLED", True)
    monkeypatch.setattr(cli, "PROVIDER_ENABLED", False, raising=False)
    result = cli.main(["--live"])
    assert result == 2
    monkeypatch.setattr(cli, "LIVE_ENABLED", False)
    assert cli.main(argv) == 2


def test_live_switch_and_script_still_refuse() -> None:
    assert LIVE_ENABLED is False
    script = ROOT / "scripts" / "loadtest.py"
    result = subprocess.run([sys.executable, str(script), "--live"], capture_output=True, text=True, check=False)
    assert result.returncode == 2
    assert "refused" in result.stderr
    bare = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, check=False)
    assert bare.returncode == 2
    target = FakeTarget([answer("refused")])

    def refuse_transport(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("transport was called")

    client = SessionClient(
        "https://target.example",
        transport=refuse_transport,
        allowlist=Allowlist((Entry("https", "target.example", 443, "/"),)),
        budget=_budget(100),
        attestations=[],
        today=TODAY,
        rate_cap=RateCap(20),
        chat_reserve_usd=0.0,
        fake_transport=False,
    )
    with pytest.raises(LoadTestRefused, match="LIVE_ENABLED"):
        _run(client, _conn(), approved=CASES)
    with pytest.raises(LoadTestRefused, match="fake transport"):
        execute(client, _conn(), pin=PIN, fixture_pid="100", approved_cases=CASES)
    assert target.chats == 0


def _complete_report() -> LoadReport:
    """A measured 100-case live stub report. Does not open a socket or flip a source switch."""
    return LoadReport(
        cases_requested=CASES,
        cases_completed=CASES,
        orchestration_latency_seconds=2.5,
        llm_latency_seconds=1.25,
        llm_latency_samples=CASES,
        exploit_storage_rows=CASES,
        exploit_storage_write_seconds=0.4,
        exploit_storage_rows_per_second=CASES / 0.4,
        stopped_by=None,
        live=True,
        zero_cost_stub=True,
        satisfies_d13=True,
        bottleneck="orchestration",
        architectural_fix="Keep one authenticated session and send the 100 chats without repeating login or patient open.",
    )


def test_complete_report_has_no_problems_and_round_trips(tmp_path: Path) -> None:
    report = _complete_report()
    assert report.satisfies_d13 is True
    assert report_problems(report) == ()
    path = tmp_path / "d13-load.json"
    assert write_report(report, path) == ()
    saved = json.loads(path.read_text(encoding="utf-8"))
    assert saved["satisfies_d13"] is True
    assert saved["live"] is True
    assert saved["cases_completed"] == CASES
    assert saved["llm_latency_samples"] == CASES
    assert saved["stopped_by"] is None
    assert saved["bottleneck"] == "orchestration"
    again = json.loads(path.read_text(encoding="utf-8"))
    assert again == saved
    assert "question" not in path.read_text(encoding="utf-8")
    assert LIVE_ENABLED is False
    assert PROVIDER_ENABLED is False


def test_report_destination_is_fixed(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    sys.path.insert(0, str(ROOT))
    import scripts.loadtest as cli
    assert report_destination(ROOT) == ROOT / "evals" / "results" / "d13-load.json"
    assert REPORT_FILE == Path("evals") / "results" / "d13-load.json"
    report = _complete_report()
    assert cli.persist(report, tmp_path / "other.json") == 2
    assert "report path is not the D-13 destination" in capsys.readouterr().err
    assert not (tmp_path / "other.json").exists()
    allowed = tmp_path / "results" / "d13-load.json"
    assert cli.persist(report, allowed) == 0
    assert json.loads(allowed.read_text(encoding="utf-8"))["satisfies_d13"] is True


def test_mid_run_failure_keeps_partial_measurements(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agentforge.evals.loadtest.subprocess.run", _Git())
    short = _target([_sse(12.5)])
    stopped = _run(_client(short, _budget(CASES), rate=rate_cap_for(CASES) - 1), _conn())
    assert stopped.cases_completed == CASES - 1
    assert stopped.stopped_by == "refused by rate"
    assert stopped.satisfies_d13 is False
    assert stopped.llm_latency_samples == CASES - 1
    assert stopped.exploit_storage_rows == CASES - 1
    path = tmp_path / "d13-load.json"
    problems = write_report(stopped, path)
    saved = json.loads(path.read_text(encoding="utf-8"))
    assert saved["cases_completed"] == CASES - 1
    assert saved["stopped_by"] == "refused by rate"
    assert saved["satisfies_d13"] is False
    assert "case_count" in problems
    assert "completion" in problems


def test_write_failure_names_the_error_and_keeps_prior_evidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    report = _complete_report()
    path = tmp_path / "d13-load.json"
    path.write_text('{"kept": true}\n', encoding="utf-8")

    def fail_replace(self: Path, _target: Path) -> None:
        raise PermissionError(13, "operation not permitted")

    monkeypatch.setattr(Path, "replace", fail_replace)
    with pytest.raises(LoadTestRefused, match="report write failed: PermissionError errno=13 partial report kept"):
        write_report(report, path)
    assert path.read_text(encoding="utf-8") == '{"kept": true}\n'
    partial = path.with_name("d13-load.json.tmp")
    assert json.loads(partial.read_text(encoding="utf-8"))["satisfies_d13"] is True
    partial.unlink()


def test_cli_write_failure_exits_without_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    sys.path.insert(0, str(ROOT))
    import scripts.loadtest as cli

    report = _complete_report()
    destination = tmp_path / "results" / "d13-load.json"

    def fail_write(found: LoadReport, path: Path) -> tuple[str, ...]:
        raise LoadTestRefused("report write failed: PermissionError errno=13")

    monkeypatch.setattr(cli, "write_report", fail_write)
    assert cli.persist(report, destination) == 2
    captured = capsys.readouterr()
    assert "refused: report write failed" in captured.err
    assert "Traceback" not in captured.err
    assert not destination.exists()
    assert LIVE_ENABLED is False


def test_report_saves_measurements_and_rejects_incomplete_evidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agentforge.evals.loadtest.subprocess.run", _Git())
    target = _target([_sse(12.5)])
    report = _run(_client(target, _budget(1), rate=20), _conn(), count=1, approved=1)
    path = tmp_path / "d13-load.json"
    assert "case_count" in write_report(report, path)
    saved = json.loads(path.read_text(encoding="utf-8"))
    assert saved["cases_completed"] == 1
    assert saved["orchestration_latency_seconds"] >= 0
    assert saved["llm_latency_seconds"] == 0.0125
    assert saved["llm_latency_label"] == "target_stub_llm"
    assert isinstance(saved["exploit_storage_rows_per_second"], float)
    assert saved["bottleneck"] in {"orchestration", "stub_llm", "exploit_storage", "not_measured"}
    assert (saved["bottleneck"] == "not_measured") == (saved["architectural_fix"] == "not_measured")
    assert "question" not in path.read_text(encoding="utf-8")
    assert "cookie" not in path.read_text(encoding="utf-8").lower()
    incomplete = _run(_client(_target([answer("refused")]), _budget(1), rate=20), _conn(), count=1, approved=1)
    missing = set(report_problems(incomplete))
    assert {"case_count", "stub_llm_latency", "llm_samples", "bottleneck", "completion"} <= missing
    assert "not_measured" in report_json(incomplete)


def test_missing_exploit_table_refuses_before_any_request(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agentforge.evals.loadtest.subprocess.run", _Git())
    target = _target([answer("refused")])
    empty = sqlite3.connect(":memory:")
    stopped = _run(_client(target, _budget(1), rate=20), empty, count=1, approved=1)
    assert stopped.cases_completed == 0
    assert stopped.stopped_by == "exploit store is not ready"
    assert target.calls == []
    assert empty.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'exploits'").fetchone() is None
    ready = _conn()
    _require_store(ready)
    report = _run(_client(target, _budget(1), rate=20), ready, count=1, approved=1)
    assert report.cases_completed == 1
    assert ready.execute("SELECT COUNT(*) FROM exploits").fetchone() == (1,)


def test_offline_preflight_prints_names_and_opens_no_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agentforge.evals.loadtest.subprocess.run", _Git())
    checks = offline_preflight(
        live_enabled=False,
        provider_enabled=False,
        origin="https://target.example",
        pin=PIN,
        pid="100",
        revision_dir="reviewed-checkout",
        caps=Caps(5.0, 5.0, 100, 5.0, 15.0),
        allowlist=Allowlist((Entry("https", "target.example", 443, "/"),)),
        secret_set=True,
        token_set=True,
        password_set=True,
        store_ready=True,
    )
    assert all(ok for _name, ok in checks)
    assert dict(offline_preflight(
        live_enabled=False,
        provider_enabled=False,
        origin="https://target.example",
        pin=PIN,
        pid="100",
        revision_dir="reviewed-checkout",
        caps=Caps(5.0, 5.0, 100, 5.0, 15.0),
        allowlist=Allowlist((Entry("https", "target.example", 443, "/"),)),
        secret_set=True,
        token_set=True,
        password_set=True,
    ))["exploit_store"] is False
    missing = offline_preflight(
        live_enabled=False,
        provider_enabled=False,
        origin="https://other.example",
        pin=PIN,
        pid="100",
        revision_dir="reviewed-checkout",
        caps=Caps(5.0, 5.0, 100, 5.0, 15.0),
        allowlist=Allowlist((Entry("https", "target.example", 443, "/"),)),
        secret_set=False,
        token_set=True,
        password_set=True,
    )
    assert dict(missing)["allowlist_origin"] is False
    assert dict(missing)["budget_secret_set"] is False
    with pytest.raises(LoadTestRefused, match="LIVE_ENABLED"):
        offline_preflight(
            live_enabled=True,
            provider_enabled=False,
            origin="https://target.example",
            pin=PIN,
            pid="100",
            revision_dir="reviewed-checkout",
            caps=Caps(5.0, 5.0, 100, 5.0, 15.0),
            allowlist=Allowlist((Entry("https", "target.example", 443, "/"),)),
            secret_set=True,
            token_set=True,
            password_set=True,
        )
    rendered = "\n".join(f"{name}={'pass' if ok else 'fail'}" for name, ok in checks)
    assert "AGENTFORGE_BUDGET_SECRET" not in rendered
    assert all(line.endswith(("=pass", "=fail")) for line in rendered.splitlines())
    loaded = load_caps(ROOT / "config" / "budget.yaml")
    assert loaded.per_run_usd == 5.0 and loaded.hard_ceiling_per_day_usd == 15.0


def test_preflight_rejects_unverified_route_pin_and_missing_approval(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agentforge.evals.loadtest.subprocess.run", _Git())
    claude = _target([answer("refused")], ready=CLAUDE_READY, preflight_body=None)
    client = _client(claude, _budget(100), rate=20)
    report = _run(client, _conn())
    assert report.cases_completed == 0
    assert report.stopped_by == "stub_only guard is not demonstrably active"
    assert client.zero_cost_stub is False
    assert claude.chats == 0
    assert not any(url.endswith("/ready") for _method, url in claude.calls)
    wrong_pin = _target([answer("refused")])
    stopped = _run(_client(wrong_pin, _budget(100), rate=20), _conn(), revision_dir=None)
    assert stopped.cases_completed == 0
    assert stopped.stopped_by == "deployed target revision does not match the pin"
    assert wrong_pin.chats == 0
    approved = _target([answer("refused")])
    with pytest.raises(LoadTestRefused, match="approval"):
        _run(_client(approved, _budget(100), rate=20), _conn(), approved=None)
    assert approved.calls == []
