"""Per-run request cap. Enforced before the transport is called. A later 429 or 503 is not retried here."""

from __future__ import annotations


class RateCapExceeded(Exception):
    pass


class RateCap:
    def __init__(self, max_requests: int) -> None:
        if max_requests < 0:
            raise ValueError("max_requests must not be negative")
        self._max = max_requests
        self._used = 0

    @property
    def used(self) -> int:
        return self._used

    @property
    def max_requests(self) -> int:
        return self._max

    def reserve(self) -> None:
        """Count one request that is about to be sent. Raises before the call that would exceed the cap."""
        if self._used + 1 > self._max:
            raise RateCapExceeded(f"request-rate cap of {self._max} would be exceeded")
        self._used += 1
