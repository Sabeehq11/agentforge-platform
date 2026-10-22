"""R7 allowlist proposal: two path prefixes on one https origin. Proven on a temporary file, offline.

config/allowlist.yaml is not edited here. The edit is Gate B and needs its own approval. These tests show what that
edit would allow and what it would still refuse, over every URL SessionClient builds.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urljoin

import pytest
from fixtures import TODAY, FakeTarget, p6_budget

from agentforge.evals.session import (
    CHAT_PATH,
    DEMOGRAPHICS_PATH,
    DOCK_PATH,
    LOGIN_ACTION_PATH,
    SESSION_PID_PATH,
    SessionClient,
    patient_open_urls,
)
from agentforge.safety.allowlist import Allowlist
from agentforge.safety.chokepoint import RefusedByChokepoint
from agentforge.safety.identity import LOGIN_PATH
from agentforge.safety.rate import RateCap
from agentforge.safety.spend_limits import Attestation

HOST = "target.example"
ORIGIN = f"https://{HOST}"
PROPOSAL = (
    "entries:\n"
    f"  - {{scheme: https, host: {HOST}, port: 443, path_prefix: /interface}}\n"
    f"  - {{scheme: https, host: {HOST}, port: 443, path_prefix: /library/ajax}}\n"
)


def proposal(tmp_path: Path, text: str = PROPOSAL) -> Allowlist:
    path = tmp_path / "allowlist.yaml"
    path.write_text(text)
    return Allowlist.from_file(path)


def test_proposal_parses_to_exactly_two_entries(tmp_path: Path) -> None:
    entries = proposal(tmp_path).entries
    assert [(e.scheme, e.host, e.port, e.path_prefix) for e in entries] == [
        ("https", HOST, 443, "/interface"),
        ("https", HOST, 443, "/library/ajax"),
    ]


def test_every_path_the_session_client_builds_is_inside_the_two_prefixes(tmp_path: Path) -> None:
    allow = proposal(tmp_path)
    demographics, readback, _ = patient_open_urls(ORIGIN, "100", "csrf")
    built = [
        urljoin(ORIGIN + "/", LOGIN_PATH.lstrip("/")) + "?site=default",
        urljoin(ORIGIN + "/", LOGIN_ACTION_PATH.lstrip("/")) + "?auth=login&site=default",
        urljoin(ORIGIN + "/", DOCK_PATH.lstrip("/")) + "?site=default",
        urljoin(ORIGIN + "/", CHAT_PATH.lstrip("/")),
        demographics,
        readback,
    ]
    assert DEMOGRAPHICS_PATH.startswith("/interface") and SESSION_PID_PATH.startswith("/library/ajax")
    for url in built:
        assert allow.check(url).allowed, url


def _client(target: FakeTarget, allow: Allowlist) -> SessionClient:
    client = SessionClient(
        ORIGIN,
        transport=target,
        allowlist=allow,
        budget=p6_budget(),
        attestations=[Attestation("target", "target-key", 10.0, "someone", TODAY)],
        provider="target",
        today=TODAY,
        rate_cap=RateCap(60),
        fake_transport=True,
    )
    client.accept_authenticated_stub_guard()
    return client


def test_full_session_flow_runs_under_the_two_prefixes_and_stays_inside_them(tmp_path: Path) -> None:
    target = FakeTarget(login_redirect=True)
    allow = proposal(tmp_path)
    client = _client(target, allow)
    client.verify_identity()
    client.login(username="copilot_doc_a", password="fixture-not-a-secret")
    client.read_dock()
    client.open_patient("100")
    client.session.patient_context_confirmed = True
    client.post_chat("hello")
    assert target.calls, "the flow sent nothing, so the test proves nothing"
    for _method, url in target.calls:
        assert allow.check(url).allowed, url


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://evil.example/interface/chat.php",
        "http://target.example/interface/chat.php",
        "/admin/chat.php",
        "/apis/default/api/patient",
        "/portal/index.php",
        "/oauth2/default/token",
    ],
)
def test_a_hostile_dock_endpoint_is_refused_and_never_sent(tmp_path: Path, endpoint: str) -> None:
    target = FakeTarget(login_redirect=True, dock_endpoint=endpoint)
    client = _client(target, proposal(tmp_path))
    client.verify_identity()
    client.login(username="copilot_doc_a", password="fixture-not-a-secret")
    client.read_dock()
    client.session.patient_context_confirmed = True
    sent_before = len(target.calls)
    with pytest.raises(RefusedByChokepoint):
        client.post_chat("hello")
    assert len(target.calls) == sent_before


@pytest.mark.parametrize(
    "url",
    [
        f"{ORIGIN}/admin/index.php",
        f"{ORIGIN}/apis/default/api/patient",
        f"{ORIGIN}/portal/index.php",
        f"{ORIGIN}/oauth2/default/authorize",
        f"{ORIGIN}/library/other.php",
        f"{ORIGIN}/library",
        f"{ORIGIN}/interfaceX/login.php",
        f"{ORIGIN}/library/ajaxx/set_pt.php",
        f"{ORIGIN}/",
        f"{ORIGIN}/interface/../admin/index.php",
        f"{ORIGIN}/interface/%2e%2e/admin/index.php",
        "https://other.example/interface/login/login.php",
        f"http://{HOST}/interface/login/login.php",
        f"http://{HOST}:80/interface/login/login.php",
        f"https://{HOST}:8443/interface/login/login.php",
        f"https://user:pass@{HOST}/interface/login/login.php",
        f"https://{HOST}\\@evil.example/interface/login/login.php",
        f"ftp://{HOST}/interface/login/login.php",
    ],
)
def test_off_list_urls_are_refused(tmp_path: Path, url: str) -> None:
    assert not proposal(tmp_path).check(url).allowed


@pytest.mark.parametrize(
    "location",
    [
        "/admin/index.php",
        "https://evil.example/interface/main/tabs/main.php",
        f"http://{HOST}/interface/main/tabs/main.php",
        "/interface/../portal/index.php",
    ],
)
def test_off_list_redirects_are_refused(tmp_path: Path, location: str) -> None:
    allow = proposal(tmp_path)
    current = f"{ORIGIN}/interface/main/main_screen.php"
    assert not allow.check_redirect(current, location).allowed


def test_an_on_list_redirect_is_allowed(tmp_path: Path) -> None:
    allow = proposal(tmp_path)
    current = f"{ORIGIN}/interface/main/main_screen.php"
    assert allow.check_redirect(current, "/interface/main/tabs/main.php?token_main=once").allowed


@pytest.mark.parametrize("text", ["", "entries: []", "{{{ bad", "entries: nope"])
def test_an_empty_or_unreadable_file_denies_everything(tmp_path: Path, text: str) -> None:
    assert not proposal(tmp_path, text).check(f"{ORIGIN}/interface/login/login.php").allowed


def test_one_bad_entry_voids_the_whole_proposal(tmp_path: Path) -> None:
    text = PROPOSAL + "  - {scheme: https, host: '*.example', port: 443, path_prefix: /}\n"
    allow = proposal(tmp_path, text)
    assert allow.entries == ()
    assert not allow.check(f"{ORIGIN}/interface/login/login.php").allowed
