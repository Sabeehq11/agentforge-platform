"""Shared helpers for the gate validators. Local file reads only."""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, date, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

import yaml

_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
# Words that mean a record is carrying a credential. A record may name a key by label only.
_SECRET_KEY_NAMES = (
    "password",
    "secret",
    "token",
    "apikey",
    "api_key",
    "authorization",
    "cookie",
)
_SECRET_VALUE = re.compile(r"(sk-[A-Za-z0-9_-]{8,}|Bearer\s+\S{8,})")
_PLACEHOLDERS = frozenset(
    {"", "todo", "tbd", "changeme", "fill me", "fill-me", "<fill>", "none"}
)


_LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_PUBLIC_PREFIXES = ("/interface", "/library/ajax")


def merge_public_host(data: Any, host: str) -> dict[str, Any]:
    """Return allowlist data with localhost entries kept and exactly one public host added.

    A blank host returns the original data unchanged. A wildcard or a second public host is not accepted: the
    caller must not pass one. Existing public entries are replaced so a stale tunnel hostname cannot linger.
    """
    base = data if isinstance(data, dict) else {}
    name = host.strip()
    if not name:
        return base
    raw = base.get("entries")
    kept = []
    if isinstance(raw, list):
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            if str(entry.get("host", "")).lower() in _LOCAL_HOSTS:
                kept.append(entry)
    merged = dict(base)
    public = name.lower().rstrip(".")
    merged["entries"] = [
        *kept,
        *(
            {"scheme": "https", "host": public, "port": 443, "path_prefix": prefix}
            for prefix in _PUBLIC_PREFIXES
        ),
    ]
    return merged


def load_mapping(path: Path) -> dict[str, Any] | None:
    """A missing, unreadable or non-mapping file is None, so the caller treats it as absent."""
    try:
        data: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return None
    return data if isinstance(data, dict) else None


def is_blank(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip().lower() in _PLACEHOLDERS
    return False


_DNS_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_TLD = re.compile(r"^([a-z]{2,63}|xn--[a-z0-9-]{1,59})$")
_NON_PUBLIC_SUFFIXES = (
    ".localhost",
    ".local",
    ".localdomain",
    ".internal",
    ".lan",
    ".home",
    ".corp",
    ".intranet",
)


def public_hostname_problem(host: str) -> str | None:
    """Why a host is not a public DNS hostname, or None.

    Accepts only a dotted name whose last label is alphabetic (or `xn--`), so every IP literal is refused: IPv6, dotted
    decimal, short forms such as 127.1, a single integer, and hex or octal forms such as 0x7f.1. It also refuses
    single-label names and the usual private suffixes. A name that passes is still only a syntax check. It does not
    resolve the name and says nothing about who owns it.
    """
    name = host.strip().lower()
    if not name:
        return "host is empty"
    try:
        ipaddress.ip_address(name)
    except ValueError:
        pass
    else:
        return "host is an IP address, not a public hostname"
    if ":" in name or "[" in name or "]" in name:
        return "host is not a plain DNS name (IPv6 literals are not allowed)"
    labels = name.split(".")
    if len(labels) < 2:
        return "host has a single label, so it is not a public hostname"
    if len(name) > 253 or not all(_DNS_LABEL.match(label) for label in labels):
        return "host is not a valid DNS name (an empty label, a bad character, or a trailing dot)"
    if not _TLD.match(labels[-1]):
        return "last label is not alphabetic, so the host may be an IP address in a legacy form"
    if any(name.endswith(suffix) for suffix in _NON_PUBLIC_SUFFIXES):
        return "host uses a private or local suffix"
    return None


def is_hex40(value: Any) -> bool:
    return isinstance(value, str) and bool(_HEX40.match(value))


def is_hex64(value: Any) -> bool:
    return isinstance(value, str) and bool(_HEX64.match(value))


def secret_problems(record: dict[str, Any], where: str) -> list[str]:
    """A record must not carry a credential: no secret-named key, no key-shaped or bearer-shaped value."""
    problems: list[str] = []

    def walk(node: Any, path: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                name = str(key).lower()
                if any(word in name for word in _SECRET_KEY_NAMES):
                    problems.append(
                        f"{where}: field {path}{key} looks like a credential and must not be recorded"
                    )
                walk(value, f"{path}{key}.")
        elif isinstance(node, list):
            for index, item in enumerate(node):
                walk(item, f"{path}{index}.")
        elif isinstance(node, str) and _SECRET_VALUE.search(node):
            problems.append(
                f"{where}: value at {path.rstrip('.')} looks like a credential"
            )

    walk(record, "")
    return problems


def parse_utc(value: Any) -> datetime | None:
    """An ISO timestamp as an aware UTC datetime, or None. A naive value is read as UTC."""
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    return (
        parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
    )


def parse_date(value: Any) -> date | None:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        try:
            return date.fromisoformat(value.strip())
        except ValueError:
            return None
    return None


def to_decimal(value: Any) -> Decimal | None:
    """A non-negative finite amount. A bool, a NaN and a negative number are None."""
    if isinstance(value, bool) or value is None:
        return None
    try:
        amount = Decimal(str(value))
    except InvalidOperation:
        return None
    if not amount.is_finite() or amount < 0:
        return None
    return amount
