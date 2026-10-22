"""P3 envelope: refusal log, rate cap, identity check, PHI scan, and the authoritative kill switch."""

from __future__ import annotations

import os
from datetime import date
from pathlib import Path

import pytest

from agentforge.safety import chokepoint
from agentforge.safety.allowlist import Allowlist, Entry
from agentforge.safety.operator_approval import OperatorApproval
from agentforge.safety.budget import Budget, Caps, approval_token, load_caps
from agentforge.safety.chokepoint import RefusedByChokepoint, Response, request
from agentforge.safety.identity import IdentityMismatch, check_login_page
from agentforge.safety.phi import PhiRefused, require_clean, scan
from agentforge.safety.rate import RateCap, RateCapExceeded
from agentforge.safety.refusal_log import RefusalLog
from agentforge.safety.spend_limits import Attestation

SECRET = "test-secret-not-a-real-credential"
TODAY = date(2026, 10, 20)
URL = "https://target.example/interface/login/login.php"
CAPS = Caps(1.0, 2.0, 5, 5.0, 10.0)
ATT = [Attestation("target", "target-key", 10.0, "someone", date(2026, 10, 17))]


class Spy:
    def __init__(self, response: Response | None = None) -> None:
        self.calls: list[tuple[str, str]] = []
        self.response = response or Response(200, b"ok")

    def __call__(self, method: str, url: str) -> Response:
        self.calls.append((method, url))
        return self.response


def good_budget() -> Budget:
    budget = Budget(CAPS)
    budget.approve(approval_token(CAPS, SECRET), SECRET)
    return budget


def allow() -> Allowlist:
    return Allowlist((Entry("https", "target.example", 443, "/"),))


def call(spy: Spy, **over: object) -> Response:
    kw: dict[str, object] = dict(
        transport=spy,
        allowlist=allow(),
        budget=good_budget(),
        attestations=ATT,
        provider="target",
        est_cost_usd=0.05,
        today=TODAY,
        fake_transport=True,
        approvals=[OperatorApproval("op", TODAY, "public-target", 0.0, "fixture", "https://target.example")],
    )
    kw.update(over)
    return request("GET", URL, **kw)  # type: ignore[arg-type]


def test_live_constant_is_false() -> None:
    assert chokepoint.LIVE_ENABLED is False


def test_env_flag_cannot_bypass_live_kill_switch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTFORGE_LIVE", "1")
    monkeypatch.setenv("LIVE_ENABLED", "true")
    monkeypatch.setenv("AGENTFORGE_LIVE_ENABLED", "yes")
    monkeypatch.setenv("AGENTFORGE_LIVE_OPT_IN", "true")
    spy = Spy()
    with pytest.raises(RefusedByChokepoint) as caught:
        call(spy, fake_transport=False)
    assert caught.value.gate == "live"
    assert spy.calls == []
    assert os.environ["AGENTFORGE_LIVE"] == "1"


def test_exact_opt_in_token_enables_both_switches_and_anything_else_does_not(monkeypatch: pytest.MonkeyPatch) -> None:
    from agentforge.safety.chokepoint import OPT_IN_ENV, apply_runtime_opt_in

    monkeypatch.delenv(OPT_IN_ENV, raising=False)
    assert apply_runtime_opt_in() is False
    assert chokepoint.LIVE_ENABLED is False and chokepoint.PROVIDER_ENABLED is False
    for value in ("", "true", "1", "yes", "LIVE"):
        monkeypatch.setenv(OPT_IN_ENV, value)
        assert apply_runtime_opt_in() is False
        assert chokepoint.LIVE_ENABLED is False and chokepoint.PROVIDER_ENABLED is False
    monkeypatch.setenv(OPT_IN_ENV, "live")
    try:
        assert apply_runtime_opt_in() is True
        assert chokepoint.LIVE_ENABLED is True and chokepoint.PROVIDER_ENABLED is True
    finally:
        monkeypatch.delenv(OPT_IN_ENV)
        apply_runtime_opt_in()
    assert chokepoint.LIVE_ENABLED is False and chokepoint.PROVIDER_ENABLED is False


def test_refusal_log_omits_cookie_csrf_and_body(tmp_path: Path) -> None:
    log = RefusalLog(tmp_path / "refusals.log")
    seen: list[object] = []

    def transport(method: str, url: str, headers: dict[str, str] | None = None, body: bytes | str | None = None) -> Response:
        seen.append(body)
        return Response(200, b"ok")

    with pytest.raises(RefusedByChokepoint):
        request(
            "POST",
            "https://evil.example/interface/login/login.php",
            transport=transport,
            allowlist=allow(),
            budget=good_budget(),
            attestations=ATT,
            provider="target",
            est_cost_usd=0.05,
            today=TODAY,
            fake_transport=True,
            refusal_log=log,
            headers={"Cookie": "OpenEMR=fixture-session", "X-CSRF-Token": "fixture-csrf"},
            body="clearPass=not-committed",
        )
    text = (tmp_path / "refusals.log").read_text(encoding="utf-8")
    assert "fixture-session" not in text
    assert "fixture-csrf" not in text
    assert "not-committed" not in text
    assert "clearPass" not in text
    assert seen == []


def test_off_list_url_is_logged_and_refused(tmp_path: Path) -> None:
    log = RefusalLog(tmp_path / "refusals.log")
    spy = Spy()
    with pytest.raises(RefusedByChokepoint) as caught:
        call(spy, allowlist=Allowlist(), refusal_log=log)
    assert caught.value.gate == "allowlist"
    assert spy.calls == []
    text = (tmp_path / "refusals.log").read_text(encoding="utf-8")
    assert "gate=allowlist" in text
    assert "host=target.example" in text
    assert "interface/login" not in text
    assert SECRET not in text


def test_off_list_redirect_is_logged_and_not_followed(tmp_path: Path) -> None:
    log = RefusalLog(tmp_path / "refusals.log")
    spy = Spy(Response(302, b"secret-body", "https://evil.example/steal"))
    with pytest.raises(RefusedByChokepoint) as caught:
        call(spy, refusal_log=log)
    assert caught.value.gate == "allowlist"
    assert spy.calls == [("GET", URL)]
    text = (tmp_path / "refusals.log").read_text(encoding="utf-8")
    assert "off-list redirect refused" in text
    assert "evil.example" not in text
    assert "secret-body" not in text


def test_rate_cap_stops_before_the_next_call() -> None:
    cap = RateCap(1)
    spy = Spy()
    assert call(spy, rate_cap=cap).status == 200
    with pytest.raises(RefusedByChokepoint) as caught:
        call(spy, rate_cap=cap)
    assert caught.value.gate == "rate"
    assert len(spy.calls) == 1


def test_rate_cap_reserve_raises_before_increment() -> None:
    cap = RateCap(0)
    with pytest.raises(RateCapExceeded):
        cap.reserve()
    assert cap.used == 0


def test_rate_limit_response_is_not_retried() -> None:
    spy = Spy(Response(429, b"slow"))
    assert call(spy, rate_cap=RateCap(5)).status == 429
    assert len(spy.calls) == 1


def test_gate_order_rate_after_attestation() -> None:
    cap = RateCap(1)
    with pytest.raises(RefusedByChokepoint) as caught:
        call(Spy(), attestations=[], rate_cap=cap)
    assert caught.value.gate == "spend_limit"
    assert cap.used == 0


def test_identity_rejects_missing_fingerprint() -> None:
    with pytest.raises(IdentityMismatch):
        check_login_page(Response(200, b"<html>other product</html>"))


def test_identity_rejects_redirect_without_following() -> None:
    with pytest.raises(IdentityMismatch) as caught:
        check_login_page(Response(302, b"", "https://evil.example/"))
    assert "redirect" in caught.value.reason


def test_identity_accepts_reviewed_fingerprint() -> None:
    check_login_page(Response(200, b"<title>OpenEMR Login</title>"))


def test_phi_fixture_refused_before_write(tmp_path: Path) -> None:
    dirty = "contact 555-010-0199 or user@example.com"
    assert scan(dirty)
    with pytest.raises(PhiRefused):
        require_clean(dirty)
    target = tmp_path / "transcript.txt"
    assert not target.exists()


def test_clean_synthetic_fixture_accepted() -> None:
    require_clean("Synthetic intake note. CANARY-AF-PI2. Fixture patient 100.")


def test_identity_rejects_non_utf8_and_empty_fingerprint() -> None:
    with pytest.raises(IdentityMismatch):
        check_login_page(Response(200, b"\xff"))
    with pytest.raises(IdentityMismatch):
        check_login_page(Response(200, b"OpenEMR"), fingerprint="")
    with pytest.raises(IdentityMismatch):
        check_login_page(Response(500, b"OpenEMR"))


def test_rate_cap_rejects_negative() -> None:
    with pytest.raises(ValueError):
        RateCap(-1)


def test_refusal_log_unparsed_url_and_disabled_log(tmp_path: Path) -> None:
    log = RefusalLog(None)
    log.record("live", "disabled", "https://target.example/")
    written = RefusalLog(tmp_path / "refusals.log")
    written.record("allowlist", "bad", "http://[")
    assert "host=-" in (tmp_path / "refusals.log").read_text(encoding="utf-8")


class FakeResponse:
    def __init__(self, status: int, body: bytes, headers: list[tuple[str, str]]) -> None:
        self.status = status
        self._body = body
        self._headers = headers

    def read(self) -> bytes:
        return self._body

    def getheader(self, name: str) -> str | None:
        for key, value in self._headers:
            if key.lower() == name.lower():
                return value
        return None

    def getheaders(self) -> list[tuple[str, str]]:
        return list(self._headers)


class FakeConn:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.sent: list[tuple[str, str, bytes | None, dict[str, str]]] = []
        self.closed = False

    def request(self, method: str, path: str, body: bytes | None = None, headers: dict[str, str] | None = None) -> None:
        self.sent.append((method, path, body, dict(headers or {})))

    def getresponse(self) -> FakeResponse:
        return self.response

    def close(self) -> None:
        self.closed = True


def test_real_transport_socket_timeout_covers_openemr_chat_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    from agentforge.evals import session

    seen: list[float] = []

    def opener(host: str, port: int, timeout: float) -> FakeConn:
        del host, port
        seen.append(timeout)
        return FakeConn(FakeResponse(200, b"data: ok\n\n", []))

    assert session._SOCKET_TIMEOUT == 50.0  # noqa: SLF001
    assert session._SOCKET_TIMEOUT > 45.0  # noqa: SLF001
    monkeypatch.setattr(session, "connection_opener", opener)
    with pytest.raises(RefusedByChokepoint) as refused:
        session.real_transport("POST", "https://target.example/interface/modules/custom_modules/oe-module-copilot/public/chat.php")
    assert refused.value.gate == "live"
    assert seen == []
    monkeypatch.setattr(session, "LIVE_ENABLED", True)
    got = session.real_transport("POST", "https://target.example/interface/modules/custom_modules/oe-module-copilot/public/chat.php")
    assert got.status == 200
    assert seen == [50.0]


def test_real_transport_refuses_before_opener_while_live_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    from agentforge.evals import session

    def opener(host: str, port: int, timeout: float) -> FakeConn:
        del host, port, timeout
        raise AssertionError("socket opened while LIVE_ENABLED is false")

    monkeypatch.setattr(session, "connection_opener", opener)
    with pytest.raises(RefusedByChokepoint) as caught:
        session.real_transport("GET", "https://target.example/login.php")
    assert caught.value.gate == "live"


def test_real_transport_returns_redirect_without_following(monkeypatch: pytest.MonkeyPatch) -> None:
    from agentforge.evals import session

    conn = FakeConn(FakeResponse(302, b"", [("Location", "https://elsewhere.example/next")]))
    monkeypatch.setattr(session, "LIVE_ENABLED", True)
    monkeypatch.setattr(session, "connection_opener", lambda host, port, timeout: conn)
    got = session.real_transport("GET", "https://target.example/login.php")
    assert got.status == 302
    assert got.location == "https://elsewhere.example/next"
    assert len(conn.sent) == 1
    assert conn.closed


def test_real_transport_returns_429_once(monkeypatch: pytest.MonkeyPatch) -> None:
    from agentforge.evals import session

    conn = FakeConn(FakeResponse(429, b"slow", [("Retry-After", "30")]))
    monkeypatch.setattr(session, "LIVE_ENABLED", True)
    monkeypatch.setattr(session, "connection_opener", lambda host, port, timeout: conn)
    got = session.real_transport("GET", "https://target.example/login.php")
    assert got.status == 429
    assert got.body == b"slow"
    assert len(conn.sent) == 1
    assert conn.closed


def test_request_refuses_gates_before_real_transport_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    from agentforge.evals import session

    opened: list[str] = []

    def opener(host: str, port: int, timeout: float) -> FakeConn:
        del host, port, timeout
        opened.append("opened")
        raise AssertionError("socket opened before a gate passed")

    monkeypatch.setattr(session, "connection_opener", opener)

    def transport(method: str, url: str, headers: dict[str, str] | None = None, body: bytes | str | None = None) -> Response:
        return session.real_transport(method, url, headers, body)

    monkeypatch.setattr(chokepoint, "LIVE_ENABLED", True)
    monkeypatch.setattr(session, "LIVE_ENABLED", True)
    with pytest.raises(RefusedByChokepoint) as off_list:
        request(
            "GET",
            "https://not-listed.example/interface/login/login.php",
            transport=transport,
            allowlist=allow(),
            budget=good_budget(),
            attestations=ATT,
            provider="target",
            est_cost_usd=0.05,
            today=TODAY,
            fake_transport=False,
        )
    assert off_list.value.gate == "allowlist"
    assert opened == []

    monkeypatch.setattr(chokepoint, "LIVE_ENABLED", False)
    with pytest.raises(RefusedByChokepoint) as unapproved:
        call(Spy(), transport=transport, budget=Budget(CAPS), fake_transport=False)
    assert unapproved.value.gate == "live"
    assert opened == []

    monkeypatch.setattr(chokepoint, "LIVE_ENABLED", True)
    with pytest.raises(RefusedByChokepoint) as still_unapproved:
        call(Spy(), transport=transport, budget=Budget(CAPS), fake_transport=True)
    assert still_unapproved.value.gate == "budget"
    assert opened == []

    with pytest.raises(RefusedByChokepoint) as missing:
        call(Spy(), transport=transport, attestations=[], fake_transport=True)
    assert missing.value.gate == "spend_limit"
    assert opened == []


def test_identity_get_does_not_need_a_model_key_attestation(monkeypatch: pytest.MonkeyPatch) -> None:
    from agentforge.evals.session import SessionClient
    from agentforge.safety.chokepoint import LIVE_ENABLED

    calls: list[str] = []

    def transport(method: str, url: str, headers: dict[str, str] | None = None, body: bytes | str | None = None) -> Response:
        calls.append(method + " " + url)
        return Response(200, b"OpenEMR login")

    client = SessionClient(
        "https://target.example",
        transport=transport,
        allowlist=Allowlist((Entry("https", "target.example", 443, "/"),)),
        budget=good_budget(),
        attestations=[],
        today=TODAY,
        rate_cap=RateCap(1),
        fake_transport=True,
        approvals=[OperatorApproval("op", TODAY, "public-target", 0.0, "fixture", "https://target.example")],
    )
    client.verify_identity()
    assert calls == ["GET https://target.example/interface/login/login.php?site=default"]
    client.session.patient_context_confirmed = True
    client.session.csrf = "csrf-test"
    client.session.chat_url = "https://target.example/chat.php"
    client.chat_reserve_usd = 0.05
    with pytest.raises(RefusedByChokepoint) as caught:
        client.post_chat("synthetic")
    assert caught.value.gate == "spend_limit"
    assert len(calls) == 1
    assert LIVE_ENABLED is False


def test_identity_runner_refuses_live_before_socket(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location("live_identity", Path("scripts/live_identity.py"))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    from agentforge.evals import session

    def boom(host: str, port: int, timeout: float) -> FakeConn:
        del host, port, timeout
        raise AssertionError("socket opened by the identity runner")

    monkeypatch.setattr(session, "connection_opener", boom)
    monkeypatch.delenv("AGENTFORGE_BUDGET_SECRET", raising=False)
    root = tmp_path / "repo"
    (root / "config").mkdir(parents=True)
    for name in ("allowlist.yaml", "budget.yaml", "spend_limits.yaml"):
        (root / "config" / name).write_text((Path("config") / name).read_text(encoding="utf-8"), encoding="utf-8")
    caps = load_caps(root / "config" / "budget.yaml")
    with pytest.raises(RefusedByChokepoint) as caught:
        module.run_identity(
            root,
            today=TODAY,
            token=approval_token(caps, SECRET),
            secret=SECRET,
            origin="https://target.example",
        )
    assert caught.value.gate == "live"


def test_refusal_log_omits_password(tmp_path: Path) -> None:
    log = RefusalLog(tmp_path / "refusals.log")
    log.record("live", "disabled password=super-secret", "https://user:pw@target.example/path?token=abc")
    text = (tmp_path / "refusals.log").read_text(encoding="utf-8")
    assert "target.example" in text
    assert "reason=live disabled" in text
    assert "super-secret" not in text
    assert "token=" not in text
    assert "/path" not in text
