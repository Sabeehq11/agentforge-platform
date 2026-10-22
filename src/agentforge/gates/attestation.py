"""Validate an operator-supplied deploy attestation (plan section 6).

The attestation is written by the operator, never by this platform, and it is labeled operator-attested and not
independently verified. The validator rejects a record with a missing or placeholder field, so an unfilled template
always fails. Passing it is one input to R7 Level 2. It does not accept R7 by itself, and it proves nothing about
the agent code, which is private.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from agentforge.gates.common import (
    is_blank,
    is_hex40,
    is_hex64,
    load_mapping,
    parse_utc,
    public_hostname_problem,
    secret_problems,
)
from agentforge.gates.pin import (
    CONSISTENT,
    DIFFERENCE,
    OUTCOMES,
    UNVERIFIED,
    Manifest,
    PinReport,
    compare_observed,
)

LABEL = "operator-attested"
BRANCH_PROTECTION_VALUES = frozenset({"set", "not_set", "unchecked"})
# The existing local stack. A public deployment must be a separate compose project.
EXISTING_PROJECT = "development-easy-light"


@dataclass(frozen=True)
class AttestationResult:
    problems: tuple[str, ...]
    pin: PinReport | None

    @property
    def valid(self) -> bool:
        return not self.problems


def _origin_problem(origin: Any) -> str | None:
    if not isinstance(origin, str) or is_blank(origin):
        return "origin is missing"
    parts = urlsplit(origin.strip())
    host = (parts.hostname or "").lower()
    try:
        port = parts.port
    except ValueError:
        return "origin port is not valid"
    if parts.scheme != "https":
        return "origin must be https"
    host_problem = public_hostname_problem(host)
    if host_problem is not None:
        return f"origin must be a public hostname: {host_problem}"
    if parts.username is not None or parts.password is not None:
        return "origin must not carry userinfo"
    if port not in (None, 443):
        return "origin must use port 443"
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        return "origin must be a bare scheme and host, with no path, query or fragment"
    return None


def validate_attestation(
    record: dict[str, Any] | None,
    manifest: Manifest,
    *,
    expected_route: str = "stub",
) -> AttestationResult:
    """Every problem found, plus the pin report computed from the observed values."""
    if record is None:
        return AttestationResult(("attestation is missing or unreadable",), None)
    problems: list[str] = list(secret_problems(record, "attestation"))

    if record.get("attested_by_label") != LABEL:
        problems.append(f"attested_by_label must be exactly {LABEL!r}")
    for key in ("operator", "deploy_path", "compose_project", "seeded_data_source"):
        if is_blank(record.get(key)):
            problems.append(f"{key} is missing")
    if record.get("compose_project") == EXISTING_PROJECT:
        problems.append("compose_project must differ from the existing local stack")

    start = parse_utc(record.get("window_start_utc"))
    end = parse_utc(record.get("window_end_utc"))
    if start is None or end is None:
        problems.append("window_start_utc and window_end_utc must be ISO timestamps")
    elif end <= start:
        problems.append("window_end_utc must be after window_start_utc")

    if record.get("head_sha") != manifest.commit or not is_hex40(
        record.get("head_sha")
    ):
        problems.append("head_sha does not equal the manifest commit")
    if record.get("tree_sha") != manifest.tree or not is_hex40(record.get("tree_sha")):
        problems.append("tree_sha does not equal the manifest tree")
    if record.get("git_status_porcelain_empty") is not True:
        problems.append(
            "git status --porcelain must be empty (git_status_porcelain_empty: true)"
        )

    images = record.get("image_ids")
    if (
        not isinstance(images, list)
        or not images
        or any(is_blank(item) for item in images)
    ):
        problems.append("image_ids must be a non-empty list")

    route = record.get("route")
    if route != expected_route:
        problems.append(f"route must be {expected_route!r} for this window")
    if not is_hex64(record.get("route_config_sha256")):
        problems.append(
            "route_config_sha256 must be a 64-character sha256 of the config, not its contents"
        )

    if record.get("security_gate_result") != "pass":
        problems.append("security_gate_result must be 'pass'")
    if record.get("agent_private_check") != "pass":
        problems.append("agent_private_check must be 'pass' (the operator's own check)")
    if record.get("fixture_credential_rotated") is not True:
        problems.append("fixture_credential_rotated must be true")
    if record.get("a001_confirmed") is not True:
        problems.append("a001_confirmed must be true (synthetic data only)")

    origin_problem = _origin_problem(record.get("origin"))
    if origin_problem is not None:
        problems.append(origin_problem)

    review = record.get("access_log_review")
    if (
        not isinstance(review, dict)
        or review.get("before") is not True
        or review.get("after") is not True
    ):
        problems.append(
            "access_log_review must record a review before and after the window"
        )
    elif review.get("unexplained_entries") != 0:
        problems.append(
            "access_log_review.unexplained_entries must be 0 (otherwise stop and rotate)"
        )

    if record.get("branch_protection") not in BRANCH_PROTECTION_VALUES:
        problems.append("branch_protection must be one of set, not_set, unchecked")

    declared = record.get("pin_outcome")
    pin_report = compare_observed(manifest, record.get("observed"))
    if declared not in OUTCOMES:
        problems.append(
            "pin_outcome must be consistent_with_pin, difference or unverified (never 'verified')"
        )
    elif declared != pin_report.outcome:
        problems.append(
            f"declared pin_outcome {declared!r} does not match the computed {pin_report.outcome!r}"
        )
    if pin_report.outcome == DIFFERENCE:
        problems.append(
            "pin difference: R7 is not accepted until a redeploy or a new dated pin is recorded"
        )

    return AttestationResult(tuple(problems), pin_report)


def load_and_validate(
    path: Path, manifest: Manifest, *, expected_route: str = "stub"
) -> AttestationResult:
    return validate_attestation(
        load_mapping(path), manifest, expected_route=expected_route
    )


__all__ = [
    "AttestationResult",
    "CONSISTENT",
    "DIFFERENCE",
    "UNVERIFIED",
    "load_and_validate",
    "validate_attestation",
]
