"""Append-only log of chokepoint refusals. Host, gate and reason only.

No URL path, body, cookie, password or token is written. A log write failure must not hide the refusal.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit


def host_of(url: str) -> str:
    """Hostname only. A URL that cannot be parsed contributes no host rather than its raw text."""
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return ""
    return (host or "").lower()


_REASON = {
    "allowlist": "not on allowlist",
    "budget": "budget refused",
    "spend_limit": "spend limit refused",
    "rate": "rate cap refused",
    "live": "live disabled",
}


def safe_reason(gate: str, reason: str) -> str:
    """A short fixed phrase. Caller-supplied text is not copied, so a secret in a message cannot land in the log."""
    if "redirect" in reason.lower():
        return "off-list redirect refused"
    return _REASON.get(gate, "refused")


class RefusalLog:
    def __init__(self, path: str | Path | None) -> None:
        self._path = Path(path) if path is not None else None

    def record(self, gate: str, reason: str, url: str) -> None:
        if self._path is None:
            return
        host = host_of(url)
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        line = f"{stamp} gate={gate} host={host or '-'} reason={safe_reason(gate, reason)}\n"
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(line)
