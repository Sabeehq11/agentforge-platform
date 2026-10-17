"""Target allowlist. Default deny.

An entry is an exact scheme, host, port and path prefix. A missing, empty or malformed file denies everything.
A redirect target is checked as a new URL. Adding an entry is a reviewed change to config/allowlist.yaml.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urljoin, urlsplit

import yaml

_DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True)
class Entry:
    scheme: str
    host: str
    port: int
    path_prefix: str


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


def _deny(reason: str) -> Decision:
    return Decision(False, reason)


def _parse_entry(raw: Any) -> Entry:
    if not isinstance(raw, dict):
        raise ValueError("allowlist entry must be a mapping")
    scheme = str(raw.get("scheme", "")).lower()
    host = str(raw.get("host", "")).lower()
    port = raw.get("port")
    prefix = str(raw.get("path_prefix", "/"))
    if scheme not in _DEFAULT_PORTS:
        raise ValueError(f"allowlist entry has unsupported scheme {scheme!r}")
    if not host or any(c in host for c in "*/@:\\"):
        raise ValueError(f"allowlist entry has an invalid host {host!r}")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("allowlist entry needs an explicit integer port")
    if not prefix.startswith("/"):
        raise ValueError("allowlist path_prefix must start with '/'")
    return Entry(scheme, host, port, prefix)


def _path_matches(path: str, prefix: str) -> bool:
    if prefix == "/":
        return True
    base = prefix.rstrip("/")
    return path == base or path.startswith(base + "/")


class Allowlist:
    def __init__(self, entries: tuple[Entry, ...] = ()) -> None:
        self._entries = entries

    @classmethod
    def from_file(cls, path: str | Path) -> Allowlist:
        """Load entries. A missing, empty or malformed file yields an allowlist that denies everything."""
        try:
            data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError):
            return cls(())
        if not isinstance(data, dict):
            return cls(())
        raw_entries = data.get("entries")
        if not isinstance(raw_entries, list) or not raw_entries:
            return cls(())
        try:
            return cls(tuple(_parse_entry(e) for e in raw_entries))
        except ValueError:
            # One bad entry voids the whole file. Failing closed beats partial trust.
            return cls(())

    @property
    def entries(self) -> tuple[Entry, ...]:
        return self._entries

    def check(self, url: str) -> Decision:
        if not self._entries:
            return _deny("allowlist is empty: default deny")
        try:
            parts = urlsplit(url)
            port = parts.port
        except ValueError:
            return _deny("url could not be parsed")
        scheme = parts.scheme.lower()
        if scheme not in _DEFAULT_PORTS:
            return _deny(f"scheme {scheme!r} is not allowed")
        if "@" in parts.netloc or "\\" in url:
            return _deny("userinfo or backslash in the url is not allowed")
        host = (parts.hostname or "").lower()
        if not host:
            return _deny("url has no host")
        eff_port = port if port is not None else _DEFAULT_PORTS[scheme]
        path = unquote(parts.path) or "/"
        if ".." in path.split("/"):
            return _deny("path traversal segment is not allowed")
        for e in self._entries:
            if (
                e.scheme == scheme
                and e.host == host
                and e.port == eff_port
                and _path_matches(path, e.path_prefix)
            ):
                return Decision(True, "matched allowlist entry")
        return _deny(f"{scheme}://{host}:{eff_port}{path} is not on the allowlist")

    def check_redirect(self, current_url: str, location: str) -> Decision:
        """A redirect target is a new URL and must pass on its own. An off-list redirect is refused."""
        return self.check(urljoin(current_url, location))
