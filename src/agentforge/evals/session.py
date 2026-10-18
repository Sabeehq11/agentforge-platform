"""Public-module session client. Every HTTP call goes through the chokepoint.

Pinned SHA 9f036541cf95e896db065e0c652afb75627b03c2. Identity is a GET of the public login page. Login is a form
POST of a synthetic fixture user. Chat is POST JSON to the endpoint named by data-endpoint, with X-CSRF-Token
from data-csrf. The cookie stays in memory. It is not written to a refusal log or a result file.

The open patient is the existing OpenEMR session pid. This client GETs the pinned demographics page with the
operator pid as the only set_pid value, then reads the current session pid back from library/ajax/set_pt.php.
The read-back uses mode=session_key and key=pid and does not send a set_pid writer. A match proves the current
session pid equals the operator pid after this attempt; it does not prove the session was previously empty.
Without that exact read-back, a chat case is not executed.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date
from http.client import HTTPConnection, HTTPSConnection
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit

from agentforge.evals.login import LoginRequest
from agentforge.safety.allowlist import Allowlist
from agentforge.safety.budget import Budget
from agentforge.safety.chokepoint import LIVE_ENABLED, RefusedByChokepoint, Response, Transport, request
from agentforge.safety.identity import LOGIN_PATH, IdentityMismatch, check_login_page
from agentforge.safety.rate import RateCap
from agentforge.safety.refusal_log import RefusalLog
from agentforge.safety.spend_limits import Attestation

# Relative to the site origin. Copied from the pinned public module, not invented.
CHAT_PATH = "/interface/modules/custom_modules/oe-module-copilot/public/chat.php"
DOCK_PATH = "/interface/modules/custom_modules/oe-module-copilot/public/dock.php"
DEMOGRAPHICS_PATH = "/interface/patient_file/summary/demographics.php"
SESSION_PID_PATH = "/library/ajax/set_pt.php"
_CSRF = re.compile(r"""data-csrf=["']([^"']+)["']""")
_ENDPOINT = re.compile(r"""data-endpoint=["']([^"']+)["']""")
_SSE_EVENTS = frozenset({"answer", "declined", "denied", "degraded", "error", "conversation"})


class SessionError(Exception):
    """A session step failed before a chat attack could be graded. Not a pass."""


@dataclass
class ChatTurn:
    status: int
    events: dict[str, str]
    text: str
    conversation_id: str | None


@dataclass
class TargetSession:
    """In-memory session. patient_context_confirmed is never set by a guessed request."""

    origin: str
    cookie: str | None = None
    csrf: str | None = None
    chat_url: str | None = None
    patient_context_confirmed: bool = False
    conversation_id: str | None = None
    calls: list[str] = field(default_factory=list)

    @property
    def identity_url(self) -> str:
        return urljoin(self.origin.rstrip("/") + "/", LOGIN_PATH.lstrip("/"))


def parse_sse(body: bytes | str) -> dict[str, str]:
    """Last data payload for each known event. Unknown events are ignored, not graded."""
    text = body.decode("utf-8") if isinstance(body, bytes) else body
    events: dict[str, str] = {}
    current: str | None = None
    data_lines: list[str] = []

    def flush() -> None:
        nonlocal current, data_lines
        if current in _SSE_EVENTS and data_lines:
            events[current] = "\n".join(data_lines)
        current = None
        data_lines = []

    for line in text.splitlines():
        if line.startswith("event:"):
            flush()
            current = line.removeprefix("event:").strip()
            continue
        if line.startswith("data:"):
            data_lines.append(line.removeprefix("data:").strip())
            continue
        if line.strip() == "":
            flush()
    flush()
    return events


def answer_text(events: dict[str, str]) -> str:
    """Text the graders may score. A declined or denied event is the answer, not a silent pass."""
    for name in ("answer", "declined", "denied", "degraded", "error"):
        if name not in events:
            continue
        raw = events[name]
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return raw
        if isinstance(payload, dict):
            for key in ("text", "message", "answer", "error"):
                if key in payload:
                    return str(payload[key])
        return raw
    return ""


def conversation_id_from(events: dict[str, str]) -> str | None:
    raw = events.get("conversation")
    if not raw:
        return None
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return raw.strip() or None
    if isinstance(payload, dict):
        value = payload.get("id") or payload.get("conversation_id")
        return str(value) if value else None
    if isinstance(payload, str):
        return payload
    return None


def dock_markers(html: str) -> tuple[str, str]:
    csrf = _CSRF.search(html)
    endpoint = _ENDPOINT.search(html)
    if csrf is None or endpoint is None:
        raise SessionError("authenticated dock page has no data-csrf or data-endpoint")
    return csrf.group(1), endpoint.group(1)


class SessionClient:
    """Drives the public module through an injected transport. Does not open a socket itself."""

    def __init__(
        self,
        origin: str,
        *,
        transport: Transport,
        allowlist: Allowlist,
        budget: Budget,
        attestations: list[Attestation],
        provider: str,
        today: date,
        rate_cap: RateCap,
        refusal_log: RefusalLog | None = None,
        fake_transport: bool = False,
        patient_context: Callable[[TargetSession], bool] | None = None,
    ) -> None:
        self.origin = origin.rstrip("/")
        self.transport = transport
        self.allowlist = allowlist
        self.budget = budget
        self.attestations = attestations
        self.provider = provider
        self.today = today
        self.rate_cap = rate_cap
        self.refusal_log = refusal_log
        self.fake_transport = fake_transport
        # Only a caller-supplied verified workflow may confirm patient context. The default confirms nothing.
        self.patient_context = patient_context
        self.session = TargetSession(origin=self.origin)

    def _request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | str | None = None,
    ) -> Response:
        if not LIVE_ENABLED and not self.fake_transport:
            raise RefusedByChokepoint("live", "live use is disabled (LIVE_ENABLED is False)")
        self.session.calls.append(method + " " + url.split("?", 1)[0])
        merged = dict(headers or {})
        if self.session.cookie and "Cookie" not in merged:
            merged["Cookie"] = self.session.cookie
        try:
            return request(
                method,
                url,
                transport=self.transport,
                allowlist=self.allowlist,
                budget=self.budget,
                attestations=self.attestations,
                provider=self.provider,
                est_cost_usd=0.0,
                today=self.today,
                fake_transport=self.fake_transport,
                rate_cap=self.rate_cap,
                refusal_log=self.refusal_log,
                headers=merged or None,
                body=body,
            )
        except RefusedByChokepoint:
            raise
        except OSError as exc:
            raise SessionError("transport failed after the gates passed") from exc

    def verify_identity(self) -> None:
        """GET the login page and stop on a fingerprint mismatch or a redirect. No later call on failure."""
        response = self._request("GET", self.session.identity_url)
        check_login_page(response)

    def login(self, credentials: LoginRequest) -> None:
        """POST the synthetic fixture form. The password is the body, never a log field."""
        form = urlencode(credentials.form_body())
        response = self._request(
            "POST",
            self.session.identity_url,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=form,
        )
        if response.status in (401, 403):
            raise SessionError("login refused")
        if response.status not in (200, 302, 303):
            raise SessionError(f"login status {response.status}")
        cookie = _cookie(response)
        if cookie:
            self.session.cookie = cookie

    def read_dock(self) -> None:
        """Read data-csrf and data-endpoint. Does not set patient context."""
        response = self._request("GET", urljoin(self.origin + "/", DOCK_PATH.lstrip("/")))
        if response.status != 200 or response.location:
            raise SessionError(f"dock status {response.status}")
        csrf, endpoint = dock_markers(response.body.decode("utf-8"))
        self.session.csrf = csrf
        self.session.chat_url = urljoin(self.origin + "/", endpoint)

    def open_patient(self, pid: str) -> None:
        """GET demographics with the operator pid, then read the current session pid back.

        Confirmation starts false for this attempt. A matching read-back does not prove the session was previously empty.
        """
        self.session.patient_context_confirmed = False
        if not pid.isdigit() or int(pid) <= 0:
            raise SessionError("operator pid is missing or not a positive integer")
        if not self.session.cookie:
            raise SessionError("patient open was not sent: login cookie is missing")
        if not self.session.csrf:
            raise SessionError("patient open was not sent: csrf is missing")
        demographics, readback_url, readback_body = patient_open_urls(self.origin, pid, self.session.csrf)
        verify_demographics_query(demographics, pid)
        opened = self._request("GET", demographics)
        if opened.status != 200 or opened.location:
            raise SessionError(f"patient open status {opened.status}")
        readback = self._request(
            "POST",
            readback_url,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=urlencode(readback_body),
        )
        if readback.status != 200 or readback.location or not _session_pid_matches(readback.body, pid):
            raise SessionError("session pid read-back did not match the operator pid")
        self.session.patient_context_confirmed = True

    def confirm_patient_context(self) -> bool:
        """True only when the injected verified workflow says the open patient is confirmed.

        The pinned source shows no such public step. Passing no workflow leaves every chat case unexecuted.
        """
        if self.patient_context is None:
            self.session.patient_context_confirmed = False
            return False
        confirmed = bool(self.patient_context(self.session))
        self.session.patient_context_confirmed = confirmed
        return confirmed

    def post_unauthenticated(self, url: str, body: bytes) -> Response:
        """POST with no cookie and no CSRF. Used only for the missing-authority case."""
        self.session.cookie = None
        self.session.csrf = None
        return self._request(
            "POST",
            url,
            headers={"Content-Type": "application/json", "Accept": "text/event-stream"},
            body=body,
        )

    def post_chat(self, question: str) -> ChatTurn:
        """POST one question. Requires CSRF and confirmed patient context. Does not retry 429 or 503."""
        if not self.session.patient_context_confirmed:
            raise SessionError("patient context is not confirmed; chat was not sent")
        if not self.session.csrf or not self.session.chat_url:
            raise SessionError("chat was not sent: missing csrf or endpoint")
        payload: dict[str, str] = {"question": question}
        if self.session.conversation_id:
            payload["conversation_id"] = self.session.conversation_id
        response = self._request(
            "POST",
            self.session.chat_url,
            headers={
                "Content-Type": "application/json",
                "X-CSRF-Token": self.session.csrf,
                "Accept": "text/event-stream",
            },
            body=json.dumps(payload),
        )
        if response.status in (429, 503):
            raise SessionError(f"target returned {response.status}; not retried")
        events = parse_sse(response.body) if response.body else {}
        found = conversation_id_from(events)
        if found:
            self.session.conversation_id = found
        return ChatTurn(response.status, events, answer_text(events) or response.body.decode("utf-8", "replace"), found)


def verify_demographics_query(url: str, pid: str) -> None:
    """The demographics GET may contain only set_pid, and that value must be the operator pid."""
    parts = urlsplit(url)
    if parts.path != DEMOGRAPHICS_PATH or _single_query(parts.query) != {"set_pid": pid}:
        raise SessionError("demographics GET did not contain the exact operator pid")


def patient_open_urls(origin: str, pid: str, csrf: str) -> tuple[str, str, dict[str, str]]:
    """Pinned patient-open requests. The read-back body is read-only and has no set_pid writer."""
    demographics = _checked_url(origin, DEMOGRAPHICS_PATH, {"set_pid": pid})
    body = {"mode": "session_key", "key": "pid"}
    readback = _checked_url(origin, SESSION_PID_PATH, {"csrf_token_form": csrf})
    _reject_set_pid_writer(readback, body)
    return demographics, readback, body


def _checked_url(origin: str, path: str, query: dict[str, str]) -> str:
    """Build an origin-relative URL and require its path and query to be exactly the supplied values."""
    url = urljoin(origin.rstrip("/") + "/", path.lstrip("/") + "?" + urlencode(query))
    parts = urlsplit(url)
    if parts.path != path or _single_query(parts.query) != query:
        raise SessionError("patient open request did not match the pinned path and query")
    return url


def _single_query(query: str) -> dict[str, str]:
    parsed = parse_qs(query, keep_blank_values=True, strict_parsing=True)
    if any(len(values) != 1 for values in parsed.values()):
        raise SessionError("patient open query has a repeated parameter")
    return {key: values[0] for key, values in parsed.items()}


def _reject_set_pid_writer(url: str, body: dict[str, str]) -> None:
    """The read-back is not a writer. set_pid is allowed only on the demographics GET."""
    query = _single_query(urlsplit(url).query)
    if "set_pid" in query or "set_pid" in body:
        raise SessionError("session pid read-back must not send set_pid")
    if query.keys() != {"csrf_token_form"} or body != {"mode": "session_key", "key": "pid"}:
        raise SessionError("session pid read-back parameters were not the pinned read-only pair")


def _session_pid_matches(body: bytes, pid: str) -> bool:
    """True only when set_pt.php echoed a JSON value equal to the operator pid.

    This is the current session pid after this attempt. It does not prove the session was previously empty.
    Quotes are from js_escape.
    """
    try:
        echoed = json.loads(body.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return False
    return bool(echoed == pid)


def _cookie(response: Response) -> str | None:
    headers = response.headers or {}
    for key, value in headers.items():
        if key.lower() == "set-cookie":
            return value.split(";", 1)[0]
    return None


_CONNECT_TIMEOUT = 10.0
_REDIRECTS = frozenset({301, 302, 303, 307, 308})
# Test seam only. request() still runs first. Not read from the environment and not a live bypass.
connection_opener: Callable[..., HTTPConnection] | None = None


def real_transport(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: bytes | str | None = None,
    *,
    timeout: float = _CONNECT_TIMEOUT,
) -> Response:
    """One HTTP call. Does not check allowlist, budget, or attestation; request() does that first.

    LIVE_ENABLED is checked before any connection. Redirects are returned with Location and not followed.
    429 and 503 are returned once and not retried. connection_opener is a test seam; it is not an enable flag.
    """
    if not LIVE_ENABLED:
        raise RefusedByChokepoint("live", "live use is disabled (LIVE_ENABLED is False)")
    parts = urlsplit(url)
    if not parts.hostname or parts.scheme not in ("http", "https"):
        raise RefusedByChokepoint("live", "live transport accepts only http and https URLs")
    path = parts.path or "/"
    if parts.query:
        path = path + "?" + parts.query
    payload = body.encode("utf-8") if isinstance(body, str) else body
    port = parts.port if parts.port is not None else (443 if parts.scheme == "https" else 80)
    connect = (
        connection_opener
        if connection_opener is not None
        else (HTTPSConnection if parts.scheme == "https" else HTTPConnection)
    )
    conn = connect(parts.hostname, port, timeout=timeout)
    try:
        conn.request(method, path, body=payload, headers=headers or {})
        res = conn.getresponse()
        location = res.getheader("Location") if res.status in _REDIRECTS else None
        return Response(status=res.status, body=res.read(), location=location, headers=dict(res.getheaders()))
    finally:
        conn.close()
