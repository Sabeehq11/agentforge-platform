"""P3 envelope: refusal log, rate cap, identity check, PHI scan, and the authoritative kill switch."""

from __future__ import annotations

import os
from datetime import date
from pathlib import Path

import pytest

from agentforge.safety import chokepoint
from agentforge.safety.allowlist import Allowlist, Entry
from agentforge.safety.budget import Budget, Caps, approval_token
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
ATT = [Attestation("openrouter", "k1", 10.0, "someone", date(2026, 10, 17))]


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
        provider="openrouter",
        est_cost_usd=0.05,
        today=TODAY,
        fake_transport=True,
    )
    kw.update(over)
    return request("GET", URL, **kw)  # type: ignore[arg-type]


def test_live_constant_is_false() -> None:
    assert chokepoint.LIVE_ENABLED is False


def test_env_flag_cannot_bypass_live_kill_switch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTFORGE_LIVE", "1")
    monkeypatch.setenv("LIVE_ENABLED", "true")
    monkeypatch.setenv("AGENTFORGE_LIVE_ENABLED", "yes")
    spy = Spy()
    with pytest.raises(RefusedByChokepoint) as caught:
        call(spy, fake_transport=False)
    assert caught.value.gate == "live"
    assert spy.calls == []
    assert os.environ["AGENTFORGE_LIVE"] == "1"


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
            provider="openrouter",
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


def test_refusal_log_omits_password(tmp_path: Path) -> None:
    log = RefusalLog(tmp_path / "refusals.log")
    log.record("live", "disabled password=super-secret", "https://user:pw@target.example/path?token=abc")
    text = (tmp_path / "refusals.log").read_text(encoding="utf-8")
    assert "target.example" in text
    assert "reason=live disabled" in text
    assert "super-secret" not in text
    assert "token=" not in text
    assert "/path" not in text
