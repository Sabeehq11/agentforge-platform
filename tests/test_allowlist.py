from __future__ import annotations

from pathlib import Path

import pytest

from agentforge.safety.allowlist import Allowlist, Entry

ROOT = Path(__file__).resolve().parents[1]

OK = Entry("https", "target.example", 443, "/app")


def al() -> Allowlist:
    return Allowlist((OK,))


def test_shipped_config_allows_only_the_reviewed_host() -> None:
    a = Allowlist.from_file(ROOT / "config" / "allowlist.yaml")
    assert a.entries == (Entry("http", "127.0.0.1", 8300, "/"),)
    assert a.check("http://127.0.0.1:8300/interface/login/login.php").allowed
    assert not a.check("https://accessed-supply-sen-boc.trycloudflare.com/interface/login/login.php").allowed
    denied = a.check("https://target.example/app")
    assert not denied.allowed


def test_missing_file_denies(tmp_path: Path) -> None:
    assert not Allowlist.from_file(tmp_path / "nope.yaml").check("https://target.example/app").allowed


@pytest.mark.parametrize("text", ["", "entries: []", "entries: not-a-list", "- just\n- a list", "{{{ bad yaml"])
def test_empty_or_malformed_file_denies(tmp_path: Path, text: str) -> None:
    f = tmp_path / "a.yaml"
    f.write_text(text)
    assert not Allowlist.from_file(f).check("https://target.example/app").allowed


def test_one_bad_entry_voids_the_file(tmp_path: Path) -> None:
    f = tmp_path / "a.yaml"
    f.write_text(
        "entries:\n"
        "  - {scheme: https, host: target.example, port: 443, path_prefix: /app}\n"
        "  - {scheme: https, host: '*.example', port: 443, path_prefix: /}\n"
    )
    assert not Allowlist.from_file(f).check("https://target.example/app").allowed


def test_valid_file_allows_match(tmp_path: Path) -> None:
    f = tmp_path / "a.yaml"
    f.write_text("entries:\n  - {scheme: https, host: Target.Example, port: 443, path_prefix: /app}\n")
    a = Allowlist.from_file(f)
    assert a.check("https://target.example/app/login").allowed
    assert a.check("https://TARGET.example:443/app").allowed


def test_matching_url_allowed() -> None:
    assert al().check("https://target.example/app/x").allowed


@pytest.mark.parametrize(
    "url",
    [
        "http://target.example/app",  # wrong scheme
        "https://other.example/app",  # wrong host
        "https://target.example:8443/app",  # wrong port
        "https://target.example/other",  # wrong path
        "https://target.example/application",  # prefix is not a path boundary
        "https://target.example/app/../admin",  # traversal
        "https://target.example/app/%2e%2e/admin",  # encoded traversal
        "https://allowed@evil.example/app",  # userinfo trick
        "https://target.example@evil.example/app",  # userinfo trick with allowed host first
        "https://target.example\\@evil.example/app",  # backslash trick
        "https://evil.example/app#@target.example",  # fragment trick
        "ftp://target.example/app",
        "file:///etc/passwd",
        "https:///app",
        "not a url",
        "",
        "https://target.example:99999/app",  # invalid port
    ],
)
def test_denied_urls(url: str) -> None:
    assert not al().check(url).allowed


def test_off_list_redirect_refused() -> None:
    d = al().check_redirect("https://target.example/app", "https://evil.example/app")
    assert not d.allowed


def test_relative_redirect_inside_prefix_allowed() -> None:
    assert al().check_redirect("https://target.example/app/a", "/app/b").allowed


def test_relative_redirect_leaving_prefix_refused() -> None:
    assert not al().check_redirect("https://target.example/app/a", "/admin").allowed


def test_scheme_downgrade_redirect_refused() -> None:
    assert not al().check_redirect("https://target.example/app", "http://target.example/app").allowed
