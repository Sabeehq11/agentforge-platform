"""Fail-closed scan for patterns that must not be stored.

Patterns follow the target's static PHI unit-test idea (SSN, phone, email, MRN). They are implemented here and are
not imported from the target repository. A match refuses the write. Synthetic fixture labels such as
CANARY-AF-001 are not PHI.
"""

from __future__ import annotations

import re

_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("phone", re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?(?:[-.\s]\d{3}){2}\b")),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("mrn", re.compile(r"\bMRN[:\s#-]*\d{5,}\b", re.IGNORECASE)),
)


class PhiRefused(Exception):
    def __init__(self, kinds: tuple[str, ...]) -> None:
        self.kinds = kinds
        super().__init__("phi pattern refused: " + ", ".join(kinds))


def scan(text: str) -> tuple[str, ...]:
    """Return the pattern names that matched. Empty means the text may be stored."""
    return tuple(name for name, pattern in _PATTERNS if pattern.search(text))


def require_clean(text: str) -> None:
    found = scan(text)
    if found:
        raise PhiRefused(found)
