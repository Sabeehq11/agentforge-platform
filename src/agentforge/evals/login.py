"""Public-module login shape. Password is an argument, never logged, never read from a committed file.

This module does not perform a live login. LIVE_ENABLED false means the chokepoint refuses the transport.
No MODULE_SIGNING_SECRET is accepted or stored.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LoginRequest:
    username: str
    password: str

    def public_view(self) -> dict[str, str]:
        """Safe to log. The password is not included."""
        return {"username": self.username}

    def form_body(self) -> dict[str, str]:
        if not self.username or not self.password:
            raise ValueError("synthetic identity is incomplete")
        if self.username not in {"copilot_doc_a", "copilot_doc_b", "copilot_nurse", "copilot_front"}:
            raise ValueError("username is not a synthetic fixture user")
        return {
            "authUser": self.username,
            "clearPass": self.password,
            "languageChoice": "1",
            "new_login_session_management": "1",
        }
