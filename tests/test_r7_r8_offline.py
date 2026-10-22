"""R7-R8 Build is strictly offline. These tests prove the Build code does none of: connect, call a provider, run a
process, read a secret, read `.env`, or touch the real database. They also pin the frozen state the plan promises:
both kill switches False, the allowlist on one local host, spend_limits empty, and the live entry points refusing.

Every guard raises, so a violation fails the test instead of happening. Canary values are made up.
"""

from __future__ import annotations

import ast
import builtins
import hashlib
import http.client
import importlib.util
import io
import os
import re
import socket
import sqlite3
import subprocess
import urllib.request
from collections import UserDict
from collections.abc import Callable, Iterator
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

import pytest
import yaml
from r7_support import ROOT, TODAY, build_green_root

from agentforge.gates.preflight import run_preflight
from agentforge.safety import chokepoint

BASELINE = ROOT / "data" / "r7r8-baseline.txt"
SQLITE = ROOT / "data" / "agentforge.sqlite3"
CANARIES = {
    "OPENROUTER_API_KEY": "canary-openrouter-not-real",
    "AGENTFORGE_BUDGET_SECRET": "canary-budget-not-real",
    "AGENTFORGE_FIXTURE_PASSWORD": "canary-fixture-not-real",
    "COPILOT_FIXTURE_PASSWORD": "canary-copilot-not-real",
}


class Violation(AssertionError):
    pass


class Spy(UserDict[str, str]):
    """A stand-in for os.environ that records every read of a canary name."""

    def __init__(self, data: dict[str, str], hits: list[str]) -> None:
        super().__init__(data)
        self.hits = hits

    def __getitem__(self, key: str) -> str:
        if key in CANARIES:
            self.hits.append(key)
        return super().__getitem__(key)

    def __contains__(self, key: object) -> bool:
        if isinstance(key, str) and key in CANARIES:
            self.hits.append(key)
        return super().__contains__(key)

    def get(self, key: str, default: Any = None) -> Any:
        if key in CANARIES:
            self.hits.append(key)
        return super().get(key, default)

    def copy(self) -> dict[str, str]:
        self.hits.append("<environ copy>")
        return dict(self.data)

    def __iter__(self) -> Iterator[str]:
        self.hits.append("<environ iteration>")
        return super().__iter__()


@pytest.fixture
def offline(monkeypatch: pytest.MonkeyPatch) -> dict[str, list[str]]:
    """Block every effect and record every canary or .env access. Returns the records."""
    records: dict[str, list[str]] = {"env": [], "dotenv": []}

    def refuse(what: str) -> Callable[..., Any]:
        def blocked(*_a: Any, **_k: Any) -> Any:
            raise Violation(what)

        return blocked

    monkeypatch.setattr(socket, "socket", refuse("socket"))
    monkeypatch.setattr(socket, "create_connection", refuse("create_connection"))
    monkeypatch.setattr(socket, "getaddrinfo", refuse("getaddrinfo"))
    monkeypatch.setattr(http.client.HTTPConnection, "connect", refuse("http.client connect"))
    monkeypatch.setattr(http.client.HTTPSConnection, "connect", refuse("https connect"))
    monkeypatch.setattr(urllib.request, "urlopen", refuse("urlopen"))
    monkeypatch.setattr(urllib.request.OpenerDirector, "open", refuse("opener"))
    monkeypatch.setattr(subprocess, "Popen", refuse("subprocess"))
    monkeypatch.setattr(os, "system", refuse("os.system"))
    monkeypatch.setattr(os, "popen", refuse("os.popen"))
    import agentforge.evals.session as session_module
    import agentforge.providers.transport as provider_module

    monkeypatch.setattr(session_module, "real_transport", refuse("real_transport"))
    monkeypatch.setattr(provider_module, "provider_transport", refuse("provider_transport"))

    real_connect = sqlite3.connect

    def guarded_connect(database: Any, *args: Any, **kwargs: Any) -> Any:
        name = str(database)
        if name == ":memory:" or Path(name).name.startswith(".coverage"):
            return real_connect(database, *args, **kwargs)
        raise Violation(f"sqlite3.connect({name})")

    monkeypatch.setattr(sqlite3, "connect", guarded_connect)

    real_open = builtins.open

    def watched_open(file: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(file, (str, os.PathLike)) and Path(os.fspath(file)).name == ".env":
            records["dotenv"].append(str(file))
            raise Violation(".env was opened")
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", watched_open)
    monkeypatch.setattr(io, "open", watched_open)
    real_path_open = Path.open

    def watched_path_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self.name == ".env":
            records["dotenv"].append(str(self))
            raise Violation(".env was opened")
        return real_path_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", watched_path_open)

    for name, value in CANARIES.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(os, "environ", Spy(dict(os.environ), records["env"]))
    return records


def _load(name: str) -> Any:
    spec = importlib.util.spec_from_file_location(f"r7r8_{name}", ROOT / "scripts" / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --- the Build code has no effect -----------------------------------------------------------------------------
def test_gates_and_preflight_do_nothing_but_read_local_files(offline: dict[str, list[str]], tmp_path: Path) -> None:
    results = run_preflight(ROOT, today=TODAY)
    assert not all(item.go for item in results)
    assert all(item.go for item in run_preflight(build_green_root(tmp_path), today=TODAY))
    preflight = _load("preflight_live")
    out = io.StringIO()
    with redirect_stdout(out):
        assert preflight.main(["--root", str(ROOT)]) == 1
    assert offline["env"] == [] and offline["dotenv"] == []
    for value in CANARIES.values():
        assert value not in out.getvalue()


def test_the_guards_themselves_work(offline: dict[str, list[str]]) -> None:
    with pytest.raises(Violation):
        socket.socket()
    with pytest.raises(Violation):
        http.client.HTTPSConnection("example.invalid").connect()
    with pytest.raises(Violation):
        urllib.request.urlopen("https://example.invalid")
    with pytest.raises(Violation):
        subprocess.Popen(["true"])
    with pytest.raises(Violation):
        os.system("true")
    with pytest.raises(Violation):
        os.popen("true")
    with pytest.raises(Violation):
        sqlite3.connect(str(SQLITE))
    with pytest.raises(Violation):
        open(ROOT / ".env")
    with pytest.raises(Violation):
        (ROOT / ".env").open()
    with pytest.raises(Violation):
        (ROOT / ".env").read_text()
    assert os.environ.get("OPENROUTER_API_KEY") == CANARIES["OPENROUTER_API_KEY"]
    assert set(offline["env"]) == {"OPENROUTER_API_KEY"}
    sqlite3.connect(":memory:").close()


def test_the_real_transports_fail_if_called(offline: dict[str, list[str]]) -> None:
    import agentforge.evals.session as session_module
    import agentforge.providers.transport as provider_module

    with pytest.raises(Violation):
        session_module.real_transport("GET", "https://target.example/")
    with pytest.raises(Violation):
        provider_module.provider_transport("POST", "https://openrouter.ai/api/v1/chat/completions")


_BANNED_ROOTS = {
    "os", "socket", "ssl", "http", "subprocess", "sqlite3", "requests", "httpx", "aiohttp", "asyncio",
    "multiprocessing", "ctypes", "shutil", "tempfile", "dotenv", "importlib", "pickle", "webbrowser", "smtplib",
    "ftplib", "telnetlib", "xmlrpc", "socketserver", "select", "urllib3",
}
_BANNED_PREFIXES = (
    "agentforge.safety",
    "agentforge.providers",
    "agentforge.evals.session",
    "agentforge.agents",
    "agentforge.local_env",
    "agentforge.store",
    "urllib.request",
    "urllib.error",
)
_BANNED_CALLS = {"open", "eval", "exec", "compile", "__import__", "getattr", "setattr", "input"}


def _gate_files() -> list[Path]:
    files = sorted((ROOT / "src" / "agentforge" / "gates").glob("*.py"))
    return [*files, ROOT / "scripts" / "preflight_live.py"]


@pytest.mark.parametrize("path", _gate_files(), ids=lambda p: p.name)
def test_gate_code_imports_no_network_process_database_or_secret_module(path: Path) -> None:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    problems: list[str] = []
    for node in ast.walk(tree):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            names = [module, *(f"{module}.{alias.name}" for alias in node.names)]
        for name in names:
            if name.split(".")[0] in _BANNED_ROOTS or name.startswith(_BANNED_PREFIXES):
                problems.append(f"imports {name}")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in _BANNED_CALLS:
            problems.append(f"calls {node.func.id}")
        if isinstance(node, ast.Attribute) and node.attr in {"environ", "getenv", "putenv", "system", "popen"}:
            problems.append(f"uses .{node.attr}")
    assert problems == []


def test_the_gate_package_has_no_file_beyond_the_reviewed_set() -> None:
    names = {p.name for p in (ROOT / "src" / "agentforge" / "gates").glob("*.py")}
    assert names == {"__init__.py", "common.py", "pin.py", "attestation.py", "provider_cap.py", "ceiling.py", "preflight.py"}


# --- the frozen state -----------------------------------------------------------------------------------------
def test_both_kill_switches_are_false() -> None:
    import agentforge.evals.session as session_module

    assert chokepoint.LIVE_ENABLED is False and chokepoint.PROVIDER_ENABLED is False
    assert session_module.LIVE_ENABLED is False
    text = (ROOT / "src/agentforge/safety/chokepoint.py").read_text(encoding="utf-8")
    assert re.search(r"^LIVE_ENABLED = False$", text, re.MULTILINE)
    assert re.search(r"^PROVIDER_ENABLED = False$", text, re.MULTILINE)


def test_allowlist_is_still_only_the_local_target() -> None:
    data = yaml.safe_load((ROOT / "config/allowlist.yaml").read_text(encoding="utf-8"))
    assert data["entries"] == [{"scheme": "http", "host": "127.0.0.1", "port": 8300, "path_prefix": "/"}]


def test_spend_limits_has_no_attestation() -> None:
    data = yaml.safe_load((ROOT / "config/spend_limits.yaml").read_text(encoding="utf-8"))
    assert data["attestations"] == []


def _baseline_hashes() -> dict[str, str]:
    found: dict[str, str] = {}
    section = False
    for line in BASELINE.read_text(encoding="utf-8").splitlines():
        if line.startswith("## "):
            section = line.startswith("## sha256 frozen files")
            continue
        match = re.match(r"^([0-9a-f]{64})  (\S+)$", line)
        if section and match:
            found[match.group(2)] = match.group(1)
    return found


@pytest.mark.skipif(not BASELINE.exists(), reason="no local baseline (data/ is gitignored)")
def test_frozen_files_match_the_b0_baseline() -> None:
    baseline = _baseline_hashes()
    assert len(baseline) >= 20
    changed = [
        path
        for path, digest in baseline.items()
        if hashlib.sha256((ROOT / path).read_bytes()).hexdigest() != digest
    ]
    assert changed == []


@pytest.mark.skipif(not (BASELINE.exists() and SQLITE.exists()), reason="no local baseline or database")
def test_the_real_database_is_byte_for_byte_unchanged(offline: dict[str, list[str]]) -> None:
    text = BASELINE.read_text(encoding="utf-8")
    match = re.search(r"([0-9a-f]{64})  data/agentforge\.sqlite3", text)
    assert match is not None
    run_preflight(ROOT, today=TODAY)
    assert hashlib.sha256(SQLITE.read_bytes()).hexdigest() == match.group(1)


# --- the live entry points refuse -----------------------------------------------------------------------------
def test_orchestrate_live_is_refused_without_a_call(offline: dict[str, list[str]]) -> None:
    module = _load("orchestrate")
    out = io.StringIO()
    with redirect_stdout(out):
        assert module.main(["--live"]) == 2
    assert "refused" in out.getvalue()


def test_regress_live_is_refused(offline: dict[str, list[str]]) -> None:
    module = _load("regress")
    err = io.StringIO()
    with redirect_stderr(err):
        assert module.main(["regress.py", "--live"]) == 2
    assert "refused" in err.getvalue()


@pytest.mark.parametrize(("name", "argv"), [("live_identity", None), ("live_campaign", [])])
def test_live_scripts_refuse_with_an_empty_environment(
    monkeypatch: pytest.MonkeyPatch, offline: dict[str, list[str]], name: str, argv: list[str] | None
) -> None:
    module = _load(name)
    monkeypatch.setattr(module, "load_local_env", lambda _path: None)  # never open .env
    for env_name in [*CANARIES, *(n for n in os.environ if n.startswith(("AGENTFORGE_", "COPILOT_")))]:
        monkeypatch.delitem(os.environ, env_name, raising=False)
    err = io.StringIO()
    with redirect_stderr(err):
        code = module.main() if argv is None else module.main(argv)
    assert code == 2 and "refused" in err.getvalue()
    assert offline["dotenv"] == []


def test_check_workflows_passes() -> None:
    module = _load("check_workflows")
    assert module.main(["check_workflows.py", str(ROOT)]) == 0
