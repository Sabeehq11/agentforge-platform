"""D-13 harness. One hundred sequential chats through the existing chokepoint.

This module does not set LIVE_ENABLED or PROVIDER_ENABLED, does not read either from the environment, and does
not edit a budget file. A live socket opens only when the caller supplies the real transport and the source
constant is already true. Offline tests use fake_transport.

A zero-cost run is allowed only after authenticated stub_preflight.php returns its exact fields. The
server-side guard, not this module, checks the agent ready detail. That path still counts every chat as an
attack. The default cap of 20 therefore stops the run. Raising it is a reviewed budget change, not something
this module does.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import yaml
import subprocess
import time
from dataclasses import dataclass
from urllib.parse import urlsplit
from datetime import date
from pathlib import Path
from collections.abc import Callable
from typing import Any

from agentforge.evals.session import (
    CHAT_PATH,
    SessionClient,
    SessionError,
    TargetStatusError,
    real_transport,
)
from agentforge.safety.budget import BudgetExceeded
from agentforge.safety import chokepoint as _chokepoint
from agentforge.safety.chokepoint import LIVE_ENABLED, TARGET_PROVIDER, RefusedByChokepoint, Response
from agentforge.safety.identity import LOGIN_PATH, IdentityMismatch, check_login_page
from agentforge.safety.ledger import Ledger
from agentforge.safety.phi import PhiRefused, require_clean
from agentforge.store.access import issue_grant
from agentforge.store.records import insert_exploit

CASES = 100
REPORT_FILE = Path("evals") / "results" / "d13-load.json"
_QUESTION = "synthetic load probe"
# The running agent counts 60 verified chats per user per minute and does not retry. OpenEMR wraps the 429 as 502.
# Stay under that window. This does not raise the agent limit or skip a gate.
_AGENT_CHAT_WINDOW = 60
_AGENT_CHAT_LIMIT = 59
_STUB_PREFLIGHT_PATH = "/interface/modules/custom_modules/oe-module-copilot/public/stub_preflight.php"
# The isolated agent publishes /ready on loopback only. It is not the public module and not the tunnel.
_ISOLATED_AGENT_READY = ("127.0.0.1", 18400, "/ready")
# Identity, then identity again and login. A token redirect replaces the separate dock read;
# without one, the protected dock is read next. Stub guard, demographics, and pid read-back follow.
# Either path is 7 requests. One chat request follows per case. This harness does not request /ready.
_SETUP_REQUESTS = 7
# Reviewed SHA-256 of files that may differ from pinned HEAD. Any other path, or a different hash, refuses.
# config.local.php is not in these sets: it holds secrets and is not a source revision.
# The isolated pin has no Week 1 stub endpoint. Its optional dirty files are the reviewed chart-write refusal.
_REQUIRED_REVISION_FILES: tuple[tuple[str, str], ...] = ()
# Historical Week 1 stub files. Presence is not required. A present file must still match its reviewed hash.
_WEEK1_REVISION_FILES: tuple[tuple[str, str], ...] = (
    (
        "agent/app/chat.py",
        "bec6d101c83cc16b6320b62cfb0d2dd669dc1a1940ba3fdadc0ad80a2e8e57fd",
    ),
    (
        "agent/tests/test_chat_latency_unit.py",
        "f2c76796bcabec4e8ce2616083c43cbece727033af72a43cb3a1c82cc66fd77a",
    ),
    (
        "agent/tests/test_chat_unit.py",
        "a17ee9f494c4cf1e3dab73d982d247c4ef03b02707f23283b7b9cc17bdf1430c",
    ),
    (
        "agent/tests/test_response_quality_unit.py",
        "cdb24a9b4d624d50bf0951737520baacb4ec7c9fd05b9722668bbcc68b11d478",
    ),
    (
        "interface/modules/custom_modules/oe-module-copilot/config.local.php.example",
        "4eddeeeea71139fa18124ad0bea0e248af084b04b2c3beb75263c4aa2b87cf74",
    ),
    (
        "interface/modules/custom_modules/oe-module-copilot/public/chat.php",
        "f663c78f0443cb91720aa1b133b45f59537481a6021d1a671dd61c99a2893ed3",
    ),
    (
        "interface/modules/custom_modules/oe-module-copilot/public/stub_preflight.php",
        "24ed439e4db1ba2a8b886cd85f581f27ea65262822c617f125c26816ae1cd7c6",
    ),
    (
        "interface/modules/custom_modules/oe-module-copilot/src/ModuleConfig.php",
        "df80e96295a1342aca4dc05506297011ab570c75b549a87a8d84cb6d88a34d73",
    ),
    (
        "interface/modules/custom_modules/oe-module-copilot/src/StubRouteGuard.php",
        "231df94668a35c2dbe41e05d18cdde47c149a24fb103c7a968a985688be78881",
    ),
    (
        "interface/modules/custom_modules/oe-module-copilot/src/StubRoutePreflight.php",
        "0377a993c82795fca0acbf4487a2fe5de4413a26fde909407618ca74867a9ca9",
    ),
    (
        "tests/Tests/Isolated/Modules/Copilot/StubRouteGuardIsolatedTest.php",
        "adaab1af2881069a64031d8f50eddb18b262e7ccb845a755dc0c6c957109e15b",
    ),
    (
        "tests/Tests/Isolated/Modules/Copilot/StubRoutePreflightIsolatedTest.php",
        "8fac345c070c1b7c2bebfeb5646b47b85d6bedce3c8182f2e066c81b193539ed",
    ),
)
# The isolated checkout's reviewed chart-write refusal. Optional, and only at these hashes.
_ISOLATED_REVISION_FILES: tuple[tuple[str, str], ...] = (
    (
        "agent/app/advice.py",
        "2ff91b2d6f86a4292b91dcab5dd2caa809c06c60274d39f9aa33342ffa393e8d",
    ),
    (
        "agent/tests/test_advice_unit.py",
        "0478de060238d09b18f5db10784d0326f04f471dc553beb016b675da2a5a106a",
    ),
    (
        "agent/tests/test_chat_unit.py",
        "473ef2703f5b88dcf5e6ff03234258242cb7d8a06369ce45650340b9c675468a",
    ),
)
# Other dirty files already in the checkout. Recognized only at these hashes; not required for D-13.
_BASELINE_REVISION_FILES: tuple[tuple[str, str], ...] = (
    (
        "docs/week2/DEMO_SCRIPT.md",
        "f2ebc64377a9ba7f509d5eb2bde19e75f1164f62b7ae37eac0fa6082520af292",
    ),
    (
        "docs/week3/DECISIONS.md",
        "69b95b503b884f8675abe98bb4c838ce090c0c02137675fc84b0c26bc62430b7",
    ),
    (
        "docs/week3/PROGRESS.md",
        "3dbb09cc243172692d7b0a38a9f1175559921bcef29c59e1e87914365e5a91fc",
    ),
    (
        "docs/week3/ROADMAP.md",
        "edf1a6fb1c25039905fc20d499b9b65d9bde6f449db139e2d0b4fa5b0f23a8d9",
    ),
    (
        "evals/cases_adversarial.py",
        "16d8d3b0e3cc5ed99cb6a0f1de9976c680b6439eb6fc5f3ef6857cf819390c0b",
    ),
    (
        "evals/cases_authz.py",
        "84abfdfd8cbeb4a11008511e8df9bb97ed7d73a5f9089509237bb03be1951780",
    ),
    (
        "evals/cases_failure.py",
        "d0e27a1e879c9bee1194d9ce52648e6e65056281afa935e83bd6914faf9fe6a2",
    ),
    (
        "evals/live.py",
        "04fc38b2b36898a770df5a6028f4cd5236871281af2cfe4884b94f9b4ebd233b",
    ),
    (
        "evals/results/gate-latest.md",
        "4cad4feac617e5386769e948f78ea3d60037d2516ce60e77f70d33e1e76c8c68",
    ),
    (
        "evals/results/w2-golden-latest.json",
        "5bb66962c8718435bf810207a6b341fbdd6619fa9fe4c226a65dca4556b7c9f2",
    ),
    (
        "evals/results/w2-golden-latest.md",
        "05a8f8627401cb5261a8a1830c2f0f2ab9ba21d13776a06f2348403ecf72da7b",
    ),
    (
        "evals/w2_golden.py",
        "8fff862363e821d60d14cdeb6eca06931a3e414b7d65518a8aa169be754ae621",
    ),
)
_APPROVED_REVISION_FILES = (
    _REQUIRED_REVISION_FILES + _WEEK1_REVISION_FILES + _ISOLATED_REVISION_FILES + _BASELINE_REVISION_FILES
)


class LoadTestRefused(Exception):
    """The run stopped before or during the sequence. The message names the gate, not a transcript."""


@dataclass(frozen=True)
class LoadCase:
    case_id: str
    question: str = _QUESTION


@dataclass
class LoadReport:
    cases_requested: int
    cases_completed: int
    orchestration_latency_seconds: float
    llm_latency_seconds: float | str
    llm_latency_samples: int
    exploit_storage_rows: int
    exploit_storage_write_seconds: float
    exploit_storage_rows_per_second: float | None
    stopped_by: str | None
    live: bool
    zero_cost_stub: bool
    satisfies_d13: bool
    bottleneck: str = "not_measured"
    architectural_fix: str = "not_measured"
    llm_event_absent: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "cases_requested": self.cases_requested,
            "cases_completed": self.cases_completed,
            "orchestration_latency_seconds": self.orchestration_latency_seconds,
            "llm_latency_seconds": self.llm_latency_seconds,
            "llm_latency_label": _latency_label(self),
            "llm_latency_samples": self.llm_latency_samples,
            "llm_event_absent": self.llm_event_absent,
            "exploit_storage_rows": self.exploit_storage_rows,
            "exploit_storage_write_seconds": self.exploit_storage_write_seconds,
            "exploit_storage_rows_per_second": self.exploit_storage_rows_per_second,
            "stopped_by": self.stopped_by,
            "live": self.live,
            "path": "chokepoint_session",
            "zero_cost_stub": self.zero_cost_stub,
            "satisfies_d13": self.satisfies_d13,
            "bottleneck": self.bottleneck,
            "architectural_fix": self.architectural_fix,
        }


def _live_enabled() -> bool:
    """The source constant or the runtime opt-in. A caller cannot pass a separate true value."""
    return bool(LIVE_ENABLED or _chokepoint.LIVE_ENABLED)


def _latency_label(report: LoadReport) -> str:
    """Name the span only when at least one numeric sample was kept. Zero is numeric. Missing is not."""
    measured = report.llm_latency_samples > 0 and isinstance(report.llm_latency_seconds, (int, float))
    if report.zero_cost_stub and measured:
        return "target_stub_llm"
    return "not_measured"


def bottleneck_from(
    *,
    orchestration_seconds: float,
    llm_seconds: float | str,
    llm_samples: int,
    cases_completed: int,
    storage_seconds: float,
    storage_rows: int,
    llm_event_absent: bool = False,
) -> tuple[str, str]:
    """Name the largest measured span and one change that addresses that span. Missing data is not a conclusion.

    Orchestration here is the time outside the stub model and outside the exploit write. A partial sample set
    does not stand for the cases that did not report. Equal spans are not assigned a winner. An absent stub
    event is recorded as unavailable and is not treated as a zero-duration model call.
    """
    llm_measured = llm_samples == cases_completed and cases_completed > 0 and isinstance(llm_seconds, (int, float))
    storage_measured = storage_rows == cases_completed and cases_completed > 0 and storage_seconds > 0
    if llm_event_absent:
        llm_measured = llm_samples == 0 and llm_seconds == "not_measured"
    if not llm_measured or not storage_measured or orchestration_seconds < 0:
        return "not_measured", "not_measured"
    orchestration_only = orchestration_seconds - (0.0 if llm_event_absent else float(llm_seconds)) - storage_seconds
    if orchestration_only < 0:
        return "not_measured", "not_measured"
    spans = {
        "orchestration": orchestration_only,
        "exploit_storage": storage_seconds,
    }
    if not llm_event_absent:
        spans["stub_llm"] = float(llm_seconds)
    largest = max(spans.values())
    winners = [name for name, seconds in spans.items() if seconds == largest]
    if len(winners) != 1:
        return "not_measured", "not_measured"
    name = winners[0]
    fixes = {
        "orchestration": "The harness already keeps one authenticated session: login and patient open happen once, then the 100 chats are sent. Pace chats to the agent's rolling window. A target-side limiter change would shorten the span and is not made here.",
        "stub_llm": "Bound the stub complete() call and return its measured duration without a second model hop.",
        "exploit_storage": "Write the 100 exploit rows in one transaction instead of committing each row.",
    }
    return name, fixes[name]


def rate_cap_for(cases: int = CASES) -> int:
    """Requests the sequence can send: setup, including the login redirect, plus one chat each.

    A smaller cap stops the last chat. This does not raise the attack cap or skip a gate.
    """
    if cases < 1:
        raise ValueError("case count must be positive")
    return _SETUP_REQUESTS + cases


def synthetic_cases(count: int = CASES) -> tuple[LoadCase, ...]:
    if count < 1:
        raise ValueError("case count must be positive")
    return tuple(LoadCase(f"load-{index:03d}") for index in range(1, count + 1))


def run_load(
    client: SessionClient,
    conn: sqlite3.Connection,
    cases: tuple[LoadCase, ...],
    *,
    pin: str,
    fixture_pid: str,
    approved_cases: int | None = None,
    today: date | None = None,
    revision_dir: str | None = None,
) -> LoadReport:
    """Run cases in order on one session. Stop at the first gate refusal. Do not retry 429 or 503.

    Preflight fetches identity before login. The protected dock and stub_preflight.php are fetched only after
    login, through the chokepoint. This harness does not request /ready and does not invent its body. Chat is
    not sent unless those checks match and approved_cases equals both the case count and 100.
    today is unused: the chokepoint uses the date already on the session. Approval here is the case-count grant.
    """
    del today
    if client.provider != TARGET_PROVIDER:
        raise LoadTestRefused("load test attests provider target")
    if not cases:
        raise LoadTestRefused("case list is empty")
    if approved_cases != len(cases) or (not client.fake_transport and approved_cases != CASES):
        raise LoadTestRefused("missing approval for 100 cases")
    if not pin or len(pin) > 64:
        raise LoadTestRefused("target pin is missing")
    if _live_enabled() and client.fake_transport:
        raise LoadTestRefused("fake transport is refused while live mode is enabled")
    if not _live_enabled() and not client.fake_transport:
        raise LoadTestRefused("live use is disabled (LIVE_ENABLED is False)")
    try:
        _require_store(conn)
        _preflight(client, pin, revision_dir=revision_dir)
    except LoadTestRefused as exc:
        return _stopped_report(len(cases), client, exc)
    except (SessionError, IdentityMismatch, RefusedByChokepoint) as exc:
        return _stopped_report(len(cases), client, exc)

    started = time.perf_counter()
    llm_seconds = 0.0
    llm_samples = 0
    stored = 0
    write_seconds = 0.0
    stopped: str | None = None
    completed = 0
    try:
        _prepare(client, fixture_pid)
        chat_times: list[float] = []
        for case in cases:
            if not client.fake_transport:
                _pace(chat_times)
            _one(client, conn, case, pin, fixture_pid)
            chat_times.append(time.monotonic())
            completed += 1
            # 0.0 is a measured sample. Only None means the event was missing or invalid.
            if client.last_llm_latency_s is not None:
                llm_seconds += client.last_llm_latency_s
                llm_samples += 1
            write_started = time.perf_counter()
            _store(conn, case, pin, client)
            write_seconds += time.perf_counter() - write_started
            stored += 1
    except LoadTestRefused as exc:
        stopped = str(exc)
    except RefusedByChokepoint as exc:
        stopped = f"refused by {exc.gate}"
    except (BudgetExceeded, SessionError, TargetStatusError, PhiRefused, sqlite3.Error) as exc:
        stopped = type(exc).__name__
    elapsed = time.perf_counter() - started
    complete = completed == len(cases) and stored == len(cases) and stopped is None
    llm_absent = complete and client.zero_cost_stub and _isolated_origin(client.origin) and llm_samples == 0
    named, fix = bottleneck_from(
        orchestration_seconds=elapsed,
        llm_seconds=llm_seconds if llm_samples else "not_measured",
        llm_samples=llm_samples,
        cases_completed=completed,
        storage_seconds=write_seconds,
        storage_rows=stored,
        llm_event_absent=llm_absent,
    )
    return LoadReport(
        cases_requested=len(cases),
        cases_completed=completed,
        orchestration_latency_seconds=elapsed,
        llm_latency_seconds=llm_seconds if llm_samples else "not_measured",
        llm_latency_samples=llm_samples,
        exploit_storage_rows=stored,
        exploit_storage_write_seconds=write_seconds,
        exploit_storage_rows_per_second=(stored / write_seconds) if write_seconds > 0 else None,
        stopped_by=stopped,
        live=_live_enabled() and not client.fake_transport,
        zero_cost_stub=client.zero_cost_stub,
        satisfies_d13=complete and _live_enabled() and not client.fake_transport,
        bottleneck=named,
        architectural_fix=fix,
        llm_event_absent=llm_absent,
    )


def _stopped_report(requested: int, client: SessionClient, exc: BaseException) -> LoadReport:
    """Measurements that exist before the case loop. No invented latency or bottleneck."""
    stopped = str(exc) if isinstance(exc, LoadTestRefused) else type(exc).__name__
    return LoadReport(
        cases_requested=requested,
        cases_completed=0,
        orchestration_latency_seconds=0.0,
        llm_latency_seconds="not_measured",
        llm_latency_samples=0,
        exploit_storage_rows=0,
        exploit_storage_write_seconds=0.0,
        exploit_storage_rows_per_second=None,
        stopped_by=stopped,
        live=_live_enabled() and not client.fake_transport,
        zero_cost_stub=client.zero_cost_stub,
        satisfies_d13=False,
    )


def _require_store(conn: sqlite3.Connection) -> None:
    """Refuse before any target request when the existing schema has not been applied."""
    try:
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'exploits'"
        ).fetchone()
    except sqlite3.Error as exc:
        raise LoadTestRefused("exploit store is not ready") from exc
    if row is None:
        raise LoadTestRefused("exploit store is not ready")


def _preflight(client: SessionClient, pin: str, *, revision_dir: str | None = None) -> None:
    """Fetch the login fingerprint. The commit pin is a local checkout check, not page text.

    Stub identity is not requested here. The authenticated stub_preflight.php check does that later.
    """
    prior = client.spend_role
    client.spend_role = "boundary"
    try:
        identity = client._request("GET", client.origin + LOGIN_PATH, est_cost_usd=0.0)  # noqa: SLF001
        check_login_page(identity)
        if not _deployed_pin_matches(pin, revision_dir):
            raise LoadTestRefused("deployed target revision does not match the pin")
    finally:
        client.spend_role = prior


def _deployed_pin_matches(
    pin: str,
    revision_dir: str | None,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
    reader: Callable[[Path], bytes] | None = None,
) -> bool:
    """True when HEAD is the reviewed pin and every dirty path is a reviewed hash.

    Required D-13 files must all be present. Baseline dirty files may be absent, but a present
    baseline path must match its reviewed hash. Any other path fails closed. No remote is contacted.
    """
    if not pin or len(pin) < 7 or len(pin) > 64 or any(c not in "0123456789abcdef" for c in pin.lower()):
        return False
    if not revision_dir:
        return False
    run = runner if runner is not None else subprocess.run
    try:
        head = run(
            ["git", "-C", revision_dir, "rev-parse", "--verify", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        status = run(
            ["git", "-C", revision_dir, "status", "--porcelain=v1", "--untracked-files=all"],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if head.returncode != 0 or status.returncode != 0:
        return False
    revision = head.stdout.strip().lower()
    if len(revision) != 40 or any(c not in "0123456789abcdef" for c in revision):
        return False
    if not revision.startswith(pin.lower()):
        return False
    return _approved_changes(status.stdout, revision_dir, reader or Path.read_bytes)


def _approved_hashes() -> dict[str, set[str]]:
    """One path may have more than one reviewed hash. Any other hash still fails."""
    approved: dict[str, set[str]] = {}
    for path, digest in _APPROVED_REVISION_FILES:
        approved.setdefault(path, set()).add(digest)
    return approved


def _approved_changes(status: str, revision_dir: str, reader: Callable[[Path], bytes]) -> bool:
    """Required files must all be present. Isolated and baseline files are optional but hash-pinned."""
    paths = _porcelain_paths(status)
    required = dict(_REQUIRED_REVISION_FILES)
    approved = _approved_hashes()
    if paths is None or not set(required) <= paths or paths - set(approved):
        return False
    root = Path(revision_dir).resolve()
    for path in paths:
        file = (root / path).resolve()
        if not file.is_relative_to(root):
            return False
        try:
            body = reader(file)
        except OSError:
            return False
        if hashlib.sha256(body).hexdigest() not in approved[path]:
            return False
    return True


def _porcelain_paths(status: str) -> set[str] | None:
    """Paths from porcelain v1. A rename, quote, or malformed line cannot be reviewed."""
    paths: set[str] = set()
    for line in status.splitlines():
        if not line.strip():
            continue
        if len(line) < 4 or line[2] != " ":
            return None
        path = line[3:]
        if " -> " in path or path.startswith(('"', "/")) or ".." in Path(path).parts:
            return None
        paths.add(path)
    return paths


def _require_stub_guard(client: SessionClient) -> None:
    """Accept the Week 1 stub endpoint, or the isolated agent's loopback ready body. Nothing else.

    The module path stays authenticated. The isolated path is 127.0.0.1:18400/ready and is not the tunnel.
    A missing session, a failed read, or any other provider refuses before chat.
    """
    if _isolated_origin(client.origin):
        if not _isolated_stub_ready(client):
            raise LoadTestRefused("stub_only guard is not demonstrably active")
        return
    if not client.session.cookie or not client.session.csrf:
        raise LoadTestRefused("stub guard preflight has no authenticated session")
    try:
        response = client._request(  # noqa: SLF001
            "GET",
            client.origin + _STUB_PREFLIGHT_PATH,
            headers={"X-CSRF-Token": client.session.csrf},
            est_cost_usd=0.0,
        )
    except (SessionError, RefusedByChokepoint) as exc:
        raise LoadTestRefused("stub guard preflight failed") from exc
    if not _stub_guard_accepted(response):
        raise LoadTestRefused("stub_only guard is not demonstrably active")


def _isolated_origin(origin: str) -> bool:
    """The isolated R7 HTTPS port only. A public tunnel hostname is not this path."""
    parts = urlsplit(origin.rstrip("/"))
    return parts.scheme == "https" and parts.hostname == "127.0.0.1" and parts.port == 19300 and parts.path in {"", "/"}


def _isolated_stub_ready(client: SessionClient, *, reader: Callable[[], tuple[int, bytes]] | None = None) -> bool:
    """True only when loopback /ready names the no-network stub. An OpenRouter body is false."""
    if not client.session.cookie or not client.session.csrf:
        return False
    read = reader if reader is not None else _read_isolated_ready
    try:
        status, body = read()
    except OSError:
        return False
    from agentforge.evals.session import stub_ready

    return status == 200 and stub_ready(body) is True


def _read_isolated_ready() -> tuple[int, bytes]:
    """GET the isolated agent's loopback ready route. Does not follow a redirect or print the body."""
    from http.client import HTTPConnection

    host, port, path = _ISOLATED_AGENT_READY
    conn = HTTPConnection(host, port, timeout=5)
    try:
        conn.request("GET", path)
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


def _stub_guard_accepted(response: Response) -> bool:
    """HTTP 200 and exactly the three fixed fields. Extra fields, strings, or another route are not acceptance."""
    if response.status != 200:
        return False
    try:
        body = json.loads(response.body.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return False
    # True == 1 in Python, so identity is required for the booleans. A string route still uses equality.
    return (
        isinstance(body, dict)
        and set(body) == {"stub_only", "accepted", "route"}
        and body["stub_only"] is True
        and body["accepted"] is True
        and body["route"] == "week1-stub"
    )


def _require_authenticated_dock(client: SessionClient) -> None:
    """The dock is accepted only after login, and only when it names the public chat endpoint."""
    if not client.session.cookie or not client.session.csrf:
        raise LoadTestRefused("OpenEMR dock was not read from an authenticated session")
    endpoint = urlsplit(client.session.chat_url or "").path
    if endpoint != CHAT_PATH:
        raise LoadTestRefused("OpenEMR dock has no public chat endpoint")


def _prepare(client: SessionClient, fixture_pid: str) -> None:
    """Login, then the protected dock, stub guard, and patient open. No chat is sent here."""
    prior = client.spend_role
    client.spend_role = "boundary"
    try:
        client.verify_identity()
        client.login()
        client.read_dock()
        _require_authenticated_dock(client)
        _require_stub_guard(client)
        client.open_patient(fixture_pid)
    except RefusedByChokepoint:
        raise
    except SessionError as exc:
        raise LoadTestRefused("session setup failed") from exc
    finally:
        client.spend_role = prior
    if not client.session.patient_context_confirmed:
        raise LoadTestRefused("patient context is not confirmed")
    try:
        client.accept_authenticated_stub_guard()
    except SessionError as exc:
        raise LoadTestRefused("verified stub chat cannot carry a billable reservation") from exc


def _one(client: SessionClient, conn: sqlite3.Connection, case: LoadCase, pin: str, fixture_pid: str) -> None:
    del conn, pin, fixture_pid
    require_clean(case.question)
    before = client.budget.attacks
    # A reused conversation grows the answer until the trailing latency event stays buffered.
    # Other workflows keep the id; each load case starts fresh.
    client.session.conversation_id = None
    chat = client.post_chat(case.question)
    if client.budget.attacks != before + 1:
        raise LoadTestRefused("chat did not count as an attack")
    if chat.status != 200:
        # 429 and 503 stop here. OpenEMR wraps the agent 429 as 502, so any other non-200 stops too.
        raise TargetStatusError(chat.status, None)
    if client.chat_reserve_usd not in (None, 0.0):
        raise LoadTestRefused("stub chat reserved a positive amount")
    require_clean(chat.text)


def _pace(chat_times: list[float], *, sleeper: Callable[[float], None] | None = None, now: Callable[[], float] | None = None) -> None:
    """Wait until the oldest chat in the agent window has expired. Does not send a request or raise a cap."""
    clock = now or time.monotonic
    current = clock()
    recent = [stamp for stamp in chat_times if current - stamp < _AGENT_CHAT_WINDOW]
    chat_times[:] = recent
    if len(recent) < _AGENT_CHAT_LIMIT:
        return
    delay = _AGENT_CHAT_WINDOW - (current - recent[0])
    if delay > 0:
        (sleeper or time.sleep)(delay)


def _store(conn: sqlite3.Connection, case: LoadCase, pin: str, client: SessionClient) -> None:
    """Store a PHI-clean draft. insert_exploit requires the judge grant used by the campaign loop."""
    observed = "graded" if client.last_llm_latency_s is not None or client.zero_cost_stub else "empty"
    require_clean(observed)
    insert_exploit(
        conn,
        {
            "id": "load-" + case.case_id,
            "severity": "low",
            "category": "TM-PI",
            "reproduction_steps": f"synthetic turn {case.case_id}",
            "observed_behavior": observed,
            "expected_behavior": "refuse",
            "system_version": pin,
        },
        issue_grant("judge"),
    )


def latency_line(chat: object) -> str:
    """Name whether post_chat kept a numeric latency_ms value. Zero is valid. The body is not printed."""
    value = getattr(chat, "llm_latency_ms", None)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        return "latency_ms=missing"
    return f"latency_ms={float(value):.2f}"


def probe_one_chat(
    client: SessionClient,
    *,
    pin: str,
    fixture_pid: str,
    revision_dir: str | None = None,
) -> str:
    """One authenticated chat through the existing gates. Does not skip preflight, budget, or the attack count.

    Approval is one case, not the 100-case grant. A fake transport is refused. The returned line is the
    parsed latency only: missing, or a number including 0.0. It does not contain the answer.
    """
    # fake_transport is the offline test seam. A real socket still requires the source switch and real_transport.
    if not client.fake_transport and client.transport is not real_transport:
        raise LoadTestRefused("latency probe refuses a fake transport")
    if not client.fake_transport and not _live_enabled():
        raise LoadTestRefused("live use is disabled (LIVE_ENABLED is False)")
    if client.provider != TARGET_PROVIDER:
        raise LoadTestRefused("load test attests provider target")
    if client.chat_reserve_usd not in (None, 0.0):
        raise LoadTestRefused("verified stub chat cannot carry a billable reservation")
    _preflight(client, pin, revision_dir=revision_dir)
    _prepare(client, fixture_pid)
    before = client.budget.attacks
    client.session.conversation_id = None
    chat = client.post_chat(_QUESTION)
    if client.budget.attacks != before + 1:
        raise LoadTestRefused("chat did not count as an attack")
    require_clean(chat.text)
    return latency_line(chat)


def execute(
    client: SessionClient,
    conn: sqlite3.Connection,
    *,
    pin: str,
    fixture_pid: str,
    approved_cases: int | None,
    revision_dir: str | None = None,
) -> LoadReport:
    """The live entry. fake_transport is refused here even when the source switch is still false."""
    if client.fake_transport or client.transport is not real_transport:
        raise LoadTestRefused("live entry refuses a fake transport")
    if not _live_enabled():
        raise LoadTestRefused("live use is disabled (LIVE_ENABLED is False)")
    return run_load(
        client,
        conn,
        synthetic_cases(CASES),
        pin=pin,
        fixture_pid=fixture_pid,
        approved_cases=approved_cases,
        revision_dir=revision_dir,
    )


def offline_preflight(
    *,
    live_enabled: bool,
    provider_enabled: bool,
    origin: str,
    pin: str,
    pid: str,
    revision_dir: str,
    caps: Any,
    allowlist: Any,
    secret_set: bool,
    token_set: bool,
    password_set: bool,
    store_ready: bool = False,
) -> tuple[tuple[str, bool], ...]:
    """Local checks only. Does not open a socket, log in, or read secret values.

    A true live switch refuses before any other check so this cannot run beside an enabled transport.
    """
    if live_enabled:
        raise LoadTestRefused("offline preflight refuses while LIVE_ENABLED is true")
    revision_ok = _deployed_pin_matches(pin, revision_dir)
    origin_ok = bool(origin) and allowlist.check(origin).allowed
    return (
        ("switches_off", not provider_enabled),
        ("budget_ceilings", caps.per_run_usd == 5.0 and caps.per_day_usd == 5.0 and caps.hard_ceiling_per_run_usd == 5.0 and caps.hard_ceiling_per_day_usd == 15.0),
        ("attack_cap", caps.max_attacks_per_run >= CASES or _load_attack_cap() >= CASES),
        ("allowlist_origin", origin_ok),
        ("revision", revision_ok),
        ("pid", pid.isdigit() and int(pid) > 0),
        ("budget_secret_set", secret_set),
        ("budget_token_set", token_set),
        ("fixture_password_set", password_set),
        ("rate_cap", rate_cap_for(CASES) == _SETUP_REQUESTS + CASES),
        ("exploit_store", store_ready),
    )


def _load_attack_cap(path: Path | None = None) -> int:
    """The committed cap, or a gitignored temporary cap. A malformed file does not raise the committed one."""
    overlay = Path("config/budget.local.yaml") if path is None else path
    try:
        data = yaml.safe_load(overlay.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return 0
    if not isinstance(data, dict):
        return 0
    value = data.get("max_attacks_per_run")
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= CASES else 0


def chat_url(origin: str) -> str:
    return origin.rstrip("/") + CHAT_PATH


_REPORT_FIELDS = (
    "cases_requested",
    "cases_completed",
    "orchestration_latency_seconds",
    "llm_latency_seconds",
    "llm_latency_label",
    "llm_latency_samples",
    "llm_event_absent",
    "exploit_storage_rows",
    "exploit_storage_write_seconds",
    "exploit_storage_rows_per_second",
    "bottleneck",
    "architectural_fix",
    "stopped_by",
    "live",
    "zero_cost_stub",
    "satisfies_d13",
)


def report_problems(report: LoadReport) -> tuple[str, ...]:
    """Name missing performance evidence. Does not invent a measurement or a bottleneck."""
    body = report.as_dict()
    problems: list[str] = []
    if report.cases_completed != CASES or report.cases_requested != CASES:
        problems.append("case_count")
    if not isinstance(body["orchestration_latency_seconds"], (int, float)):
        problems.append("orchestration_latency")
    absent = body["llm_event_absent"] is True
    if absent:
        if body["llm_latency_label"] != "not_measured" or body["llm_latency_seconds"] != "not_measured" or body["llm_latency_samples"] != 0:
            problems.append("stub_llm_latency")
    else:
        if body["llm_latency_label"] != "target_stub_llm" or not isinstance(body["llm_latency_seconds"], (int, float)):
            problems.append("stub_llm_latency")
        if body["llm_latency_samples"] != CASES:
            problems.append("llm_samples")
    if not isinstance(body["exploit_storage_rows_per_second"], (int, float)) or body["exploit_storage_rows"] != CASES:
        problems.append("exploit_storage_throughput")
    if body["bottleneck"] == "not_measured" or body["architectural_fix"] == "not_measured":
        problems.append("bottleneck")
    if not body["live"] or not body["zero_cost_stub"] or body["stopped_by"] is not None or not body["satisfies_d13"]:
        problems.append("completion")
    return tuple(problems)


def report_json(report: LoadReport) -> str:
    body = report.as_dict()
    if body["satisfies_d13"] and not body["live"]:
        body["satisfies_d13"] = False
    kept = {key: body[key] for key in _REPORT_FIELDS}
    text = json.dumps(kept, indent=2, sort_keys=True)
    require_clean(text)
    return text + "\n"


def report_destination(root: Path) -> Path:
    """The only D-13 report location. Callers do not choose another name."""
    return root / REPORT_FILE


def write_report(report: LoadReport, path: Path) -> tuple[str, ...]:
    """Save sanitized measurements. Incomplete evidence is named, not discarded.

    A disk or PHI failure is a LoadTestRefused. The destination is replaced only after the
    temporary file is written, so a failed write does not erase a previous report.
    """
    temporary = path.with_name(path.name + ".tmp")
    written = False
    try:
        text = report_json(report)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary.write_text(text, encoding="utf-8")
        written = True
        temporary.replace(path)
    except PhiRefused as exc:
        raise LoadTestRefused("report refused: phi") from exc
    except LoadTestRefused:
        raise
    except OSError as exc:
        errno = getattr(exc, "errno", None)
        kept = " partial report kept" if written and temporary.is_file() else ""
        raise LoadTestRefused(f"report write failed: {type(exc).__name__} errno={errno}{kept}") from exc
    else:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
    return report_problems(report)
