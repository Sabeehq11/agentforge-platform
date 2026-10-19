"""Provider-only HTTP transport. It cannot authorize or perform a target request.

PROVIDER_ENABLED is the only switch read here. The target transport keeps its own LIVE_ENABLED check, and this
function does not call it. Redirects are returned and not followed. 429 and 5xx are returned once.
"""

from __future__ import annotations

from http.client import HTTPSConnection
from urllib.parse import urlsplit

from agentforge.safety.chokepoint import PROVIDER_ENABLED, RefusedByChokepoint, Response

_HOST = "openrouter.ai"
_REDIRECTS = frozenset({301, 302, 303, 307, 308})


def provider_transport(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: bytes | str | None = None,
    *,
    timeout: float = 30.0,
) -> Response:
    """One OpenRouter call. A target host is refused before a connection, even if PROVIDER_ENABLED is true."""
    if not PROVIDER_ENABLED:
        raise RefusedByChokepoint("provider", "provider use is disabled (PROVIDER_ENABLED is False)")
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.hostname != _HOST:
        raise RefusedByChokepoint("provider", "provider transport accepts only the OpenRouter host")
    path = parts.path or "/"
    if parts.query:
        path = path + "?" + parts.query
    payload = body.encode("utf-8") if isinstance(body, str) else body
    conn = HTTPSConnection(parts.hostname, parts.port or 443, timeout=timeout)
    try:
        conn.request(method, path, body=payload, headers=headers or {})
        res = conn.getresponse()
        location = res.getheader("Location") if res.status in _REDIRECTS else None
        return Response(status=res.status, body=res.read(), location=location, headers=dict(res.getheaders()))
    finally:
        conn.close()
