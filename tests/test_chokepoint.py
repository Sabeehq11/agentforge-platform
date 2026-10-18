from __future__ import annotations

import socket
from datetime import date

import pytest

from agentforge.safety import chokepoint
from agentforge.safety.allowlist import Allowlist, Entry
from agentforge.safety.budget import Budget, Caps, approval_token
from agentforge.safety.chokepoint import RefusedByChokepoint, Response, request
from agentforge.safety.spend_limits import Attestation

SECRET = "test-secret-not-a-real-credential"
TODAY = date(2026, 10, 20)
URL = "https://target.example/app/x"
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
    b = Budget(CAPS)
    b.approve(approval_token(CAPS, SECRET), SECRET)
    return b


def allow() -> Allowlist:
    return Allowlist((Entry("https", "target.example", 443, "/app"),))


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


def test_live_is_disabled_in_p0() -> None:
    assert chokepoint.LIVE_ENABLED is False


def test_refused_without_fake_flag_even_if_all_gates_pass() -> None:
    spy = Spy()
    with pytest.raises(RefusedByChokepoint) as e:
        call(spy, fake_transport=False)
    assert e.value.gate == "live"
    assert spy.calls == []


def test_all_gates_pass_calls_transport_once() -> None:
    spy = Spy()
    assert call(spy).status == 200
    assert spy.calls == [("GET", URL)]


def test_empty_allowlist_denies_and_skips_transport() -> None:
    spy = Spy()
    with pytest.raises(RefusedByChokepoint) as e:
        call(spy, allowlist=Allowlist())
    assert e.value.gate == "allowlist"
    assert spy.calls == []


def test_unapproved_budget_denies_and_skips_transport() -> None:
    spy = Spy()
    with pytest.raises(RefusedByChokepoint) as e:
        call(spy, budget=Budget(CAPS))
    assert e.value.gate == "budget"
    assert spy.calls == []


def test_over_cap_denies_and_skips_transport() -> None:
    spy = Spy()
    with pytest.raises(RefusedByChokepoint) as e:
        call(spy, est_cost_usd=9.0)
    assert e.value.gate == "budget"
    assert spy.calls == []


def test_killed_budget_denies() -> None:
    spy = Spy()
    b = good_budget()
    b.kill()
    with pytest.raises(RefusedByChokepoint) as e:
        call(spy, budget=b)
    assert e.value.gate == "budget"
    assert spy.calls == []


def test_missing_attestation_denies_and_skips_transport() -> None:
    spy = Spy()
    with pytest.raises(RefusedByChokepoint) as e:
        call(spy, attestations=[])
    assert e.value.gate == "spend_limit"
    assert spy.calls == []


def test_gate_order_allowlist_before_budget_before_spend_limit() -> None:
    # Everything is wrong at once: the allowlist must be reported first, and no money may be reserved.
    b = Budget(CAPS)  # unapproved
    with pytest.raises(RefusedByChokepoint) as e:
        call(Spy(), allowlist=Allowlist(), budget=b, attestations=[])
    assert e.value.gate == "allowlist"
    # Allowlist fine, budget wrong, attestation wrong: budget is reported, not spend_limit.
    with pytest.raises(RefusedByChokepoint) as e2:
        call(Spy(), budget=b, attestations=[])
    assert e2.value.gate == "budget"


def test_allowlist_failure_reserves_no_money() -> None:
    b = good_budget()
    with pytest.raises(RefusedByChokepoint):
        call(Spy(), allowlist=Allowlist(), budget=b)
    assert b.run_spent == 0 and b.attacks == 0


def test_off_list_redirect_refused() -> None:
    spy = Spy(Response(302, b"", "https://evil.example/app"))
    with pytest.raises(RefusedByChokepoint) as e:
        call(spy)
    assert e.value.gate == "allowlist"
    assert len(spy.calls) == 1  # the redirect was never followed


def test_on_list_redirect_is_returned_not_followed_by_default() -> None:
    spy = Spy(Response(302, b"", "/app/y"))
    assert call(spy).status == 302
    assert len(spy.calls) == 1


def test_headers_and_body_reach_the_transport_only_after_the_gates() -> None:
    seen: list[tuple[object, object]] = []

    def transport(method: str, url: str, headers: dict[str, str] | None = None, body: bytes | str | None = None) -> Response:
        seen.append((headers, body))
        return Response(200, b"ok")

    assert request(
        "POST",
        URL,
        transport=transport,
        allowlist=allow(),
        budget=good_budget(),
        attestations=ATT,
        provider="openrouter",
        est_cost_usd=0.05,
        today=TODAY,
        fake_transport=True,
        headers={"X-CSRF-Token": "not-logged"},
        body=b'{"question":"synthetic"}',
    ).status == 200
    assert seen == [({"X-CSRF-Token": "not-logged"}, b'{"question":"synthetic"}')]
    seen.clear()
    with pytest.raises(RefusedByChokepoint):
        request(
            "POST",
            URL,
            transport=transport,
            allowlist=Allowlist(),
            budget=good_budget(),
            attestations=ATT,
            provider="openrouter",
            est_cost_usd=0.05,
            today=TODAY,
            fake_transport=True,
            headers={"Cookie": "secret"},
            body=b"secret-body",
        )
    assert seen == []


def test_no_socket_is_opened_by_any_gate_path(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: object, **_k: object) -> None:
        raise AssertionError("socket opened")

    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    call(Spy())
    with pytest.raises(RefusedByChokepoint):
        call(Spy(), allowlist=Allowlist())
