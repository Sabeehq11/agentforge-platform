"""Target identity check. Read-only GET of the public login page, matched against a reviewed fingerprint.

Does not probe /ready or /health. The tunnel does not publish the agent (ADR-002). A missing fingerprint, a
non-200, or a body that lacks the fingerprint is a mismatch. The check follows no redirect itself: the chokepoint
already refuses an off-list Location.
"""

from __future__ import annotations

from agentforge.safety.chokepoint import Response

# Reviewed fingerprint for the pinned OpenEMR login page. Changing it is a reviewed edit, not a runtime setting.
LOGIN_FINGERPRINT = "OpenEMR"
LOGIN_PATH = "/interface/login/login.php"


class IdentityMismatch(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def check_login_page(response: Response, *, fingerprint: str = LOGIN_FINGERPRINT) -> None:
    if response.status in (301, 302, 303, 307, 308):
        raise IdentityMismatch("login page redirected; identity check does not follow redirects")
    if response.status != 200:
        raise IdentityMismatch(f"login page status {response.status}, expected 200")
    if not fingerprint:
        raise IdentityMismatch("fingerprint is empty")
    try:
        body = response.body.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise IdentityMismatch("login page body is not utf-8") from exc
    if fingerprint not in body:
        raise IdentityMismatch("login page does not contain the reviewed fingerprint")
