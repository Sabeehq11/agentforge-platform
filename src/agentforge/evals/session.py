"""Public-module session client. Every HTTP call goes through the chokepoint.

Pinned SHA 9f036541cf95e896db065e0c652afb75627b03c2. Identity is a GET of the public login page. Login is a form
POST of a synthetic fixture user. Chat is POST JSON to the endpoint named by data-endpoint, with X-CSRF-Token
from data-csrf. The cookie stays in memory. It is not written to a refusal log or a result file.

That pin does not show an authorized public-module step that sets the open patient. This client does not guess a
set-pid URL, query parameter, or other endpoint, and it does not bypass session, CSRF, or patient authorization.
Without confirmed patient context, a chat case is not executed.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date
from urllib.parse import urlencode, urljoin

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
        if response.status != 200:
            raise SessionError(f"dock status {response.status}")
        csrf, endpoint = dock_markers(response.body.decode("utf-8"))
        self.session.csrf = csrf
        self.session.chat_url = urljoin(self.origin + "/", endpoint)

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


def _cookie(response: Response) -> str | None:
    headers = response.headers or {}
    for key, value in headers.items():
        if key.lower() == "set-cookie":
            return value.split(";", 1)[0]
    return None


def real_transport(method: str, url: str, headers: dict[str, str] | None = None, body: bytes | str | None = None) -> Response:
    """No socket in this checkpoint. A hostname argument cannot enable a live call.

    The body is accepted so the signature matches the widened transport, then discarded. Opening a connection is a
    later reviewed change, behind LIVE_ENABLED, and still has to pass request().
    """
    del method, url, headers, body
    if not LIVE_ENABLED:
        raise RefusedByChokepoint("live", "live use is disabled (LIVE_ENABLED is False)")
    raise RefusedByChokepoint("live", "no live client is wired in this checkpoint")
