"""Offline GO or NO-GO per gate (plan sections 4a, 7 and 10). Local files only, no network, no secret.

GO for every gate is a necessary condition for an operational step. It is not an approval. Each operational gate
(A, B, D, F and any later one) still needs your explicit approval, and passing preflight never replaces it.
On the repo as it stands the result is NO-GO, which is the expected state.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit
from datetime import date
from decimal import Decimal
from pathlib import Path
from typing import Any

from agentforge.gates.attestation import AttestationResult, load_and_validate
from agentforge.gates.ceiling import admit, load_exposure
from agentforge.gates.common import load_mapping, merge_public_host, parse_date, public_hostname_problem
from agentforge.gates.pin import (
    CONSISTENT,
    DIFFERENCE,
    UNVERIFIED,
    Manifest,
    compare_observed,
    load_manifest,
)
from agentforge.gates.provider_cap import (
    ACCEPTED,
    BLOCKED,
    BLOCKED_DEVIATION,
    local_caps_problem,
    r8_status,
    validate_deviation,
    validate_evidence,
)

DEPLOY_ATTESTATION = "Docs/attestations/deploy-attestation.yaml"
CURRENT_ORIGIN = "Docs/attestations/current-origin.yaml"
PROVIDER_EVIDENCE = "Docs/attestations/provider-cap-evidence.yaml"
PROVIDER_DEVIATION = "Docs/attestations/provider-cap-deviation.yaml"
SPEND_RECONCILIATION = "Docs/attestations/spend-reconciliation.yaml"
P_U_RECORD = "Docs/prerequisites/P-U.md"
PUBLIC_TARGET_RECORD = "Docs/prerequisites/public-target-authorization.md"
ALLOWED_PREFIXES = frozenset({"/interface", "/library/ajax"})
_LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_LINE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*):\s*(.*?)\s*$")
_COMMIT = re.compile(r"^[0-9a-f]{7,40}$")


@dataclass(frozen=True)
class GateResult:
    name: str
    go: bool
    reason: str

    @property
    def label(self) -> str:
        return "GO" if self.go else "NO-GO"


def read_record(path: Path) -> dict[str, str] | None:
    """`key: value` lines of a small markdown record. A missing file is None."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    fields: dict[str, str] = {}
    for line in text.splitlines():
        match = _LINE.match(line)
        if match and match.group(1) not in fields:
            fields[match.group(1)] = match.group(2).strip("`\"' ")
    return fields


def _flags_false(root: Path) -> GateResult:
    try:
        text = (root / "src/agentforge/safety/chokepoint.py").read_text(
            encoding="utf-8"
        )
    except OSError:
        return GateResult("flags_false", False, "chokepoint.py is unreadable")
    live = re.search(r"^LIVE_ENABLED = (\w+)$", text, re.MULTILINE)
    provider = re.search(r"^PROVIDER_ENABLED = (\w+)$", text, re.MULTILINE)
    if live is None or provider is None:
        return GateResult("flags_false", False, "a kill-switch constant was not found")
    if live.group(1) != "False" or provider.group(1) != "False":
        return GateResult(
            "flags_false",
            False,
            "LIVE_ENABLED or PROVIDER_ENABLED is not False in the committed file",
        )
    return GateResult(
        "flags_false", True, "LIVE_ENABLED and PROVIDER_ENABLED are both False"
    )


def _current_origin(root: Path, manifest: Manifest | None, today: date) -> str | None:
    """A later tunnel bound to the same pin. It never replaces the closed deploy attestation.

    Accepted only when its origin, approval, and observed pin all match. Anything else is absent, so the closed
    attestation origin remains the comparison.
    """
    if manifest is None:
        return None
    record = load_mapping(root / CURRENT_ORIGIN)
    if record is None or record.get("status") != "verified":
        return None
    origin = record.get("origin")
    if not isinstance(origin, str) or not origin.startswith("https://"):
        return None
    host = urlsplit(origin).hostname
    if host is None:
        return None
    observed = record.get("observed")
    if not isinstance(observed, dict) or compare_observed(manifest, observed).outcome != CONSISTENT:
        return None
    if record.get("head_sha") != manifest.commit or record.get("tree_sha") != manifest.tree:
        return None
    approvals = load_mapping(root / "config/operator_approval.yaml")
    items = approvals.get("approvals") if isinstance(approvals, dict) else None
    if not isinstance(items, list):
        return None
    wanted = origin.rstrip("/")
    for item in items:
        if not isinstance(item, dict) or item.get("scope") != "public-target":
            continue
        approved = parse_date(item.get("approved_on"))
        if approved is None or not 0 <= (today - approved).days <= 1:
            continue
        if str(item.get("origin", "")).rstrip("/") == wanted and item.get("max_usd") == 0:
            return origin
    return None


def _allowlist(root: Path, attested_origin: str | None) -> GateResult:
    data = load_mapping(root / "config/allowlist.yaml")
    local = load_mapping(root / "config/allowlist.local.yaml")
    if local is not None:
        host = local.get("public_host")
        if not isinstance(host, str) or not host.strip() or "*" in host:
            return GateResult(
                "allowlist_single_origin",
                False,
                "the local public-host file is present but unusable",
            )
        data = merge_public_host(data, host.strip())
    entries: Any = data.get("entries") if isinstance(data, dict) else None
    if not isinstance(entries, list) or not entries:
        return GateResult(
            "allowlist_single_origin",
            False,
            "allowlist is empty: no public origin to reach",
        )
    public: dict[tuple[str, str, int], set[str]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            return GateResult(
                "allowlist_single_origin", False, "an allowlist entry is not a mapping"
            )
        host = str(entry.get("host", "")).lower()
        if host in _LOCAL_HOSTS:
            continue
        port = entry.get("port")
        key = (
            str(entry.get("scheme", "")).lower(),
            host,
            port if isinstance(port, int) else -1,
        )
        public.setdefault(key, set()).add(str(entry.get("path_prefix", "/")))
    if not public:
        return GateResult(
            "allowlist_single_origin",
            False,
            "no public origin is on the allowlist (Gate B not done)",
        )
    if len(public) != 1:
        return GateResult(
            "allowlist_single_origin",
            False,
            "more than one public origin is on the allowlist",
        )
    (scheme, host, port), prefixes = next(iter(public.items()))
    host_problem = public_hostname_problem(host)
    if host_problem is not None:
        return GateResult(
            "allowlist_single_origin",
            False,
            f"the public origin host is not acceptable: {host_problem}",
        )
    if scheme != "https" or port != 443:
        return GateResult(
            "allowlist_single_origin",
            False,
            "the public origin must be https on port 443",
        )
    if prefixes != ALLOWED_PREFIXES:
        return GateResult(
            "allowlist_single_origin",
            False,
            "the public origin must carry exactly /interface and /library/ajax",
        )
    if attested_origin is not None:
        attested_host = (attested_origin.split("//", 1)[-1]).split("/", 1)[0].lower()
        if attested_host != host:
            return GateResult(
                "allowlist_single_origin",
                False,
                "the allowlist host differs from the attested origin",
            )
    return GateResult(
        "allowlist_single_origin",
        True,
        "exactly one public https origin with the two reviewed prefixes",
    )


def _deploy(
    root: Path, manifest: Manifest | None
) -> tuple[AttestationResult | None, list[GateResult]]:
    if manifest is None:
        return None, [
            GateResult(
                "deploy_attestation", False, "config/target_pin.yaml is unusable"
            ),
            GateResult("pin_outcome", False, "no manifest to compare against"),
        ]
    result = load_and_validate(root / DEPLOY_ATTESTATION, manifest)
    if not result.valid:
        reasons = "; ".join(result.problems[:3])
        return result, [
            GateResult("deploy_attestation", False, reasons),
            GateResult(
                "pin_outcome",
                False,
                "attestation is not valid, so no pin outcome is recorded",
            ),
        ]
    assert result.pin is not None
    pin_go = result.pin.outcome in (CONSISTENT, UNVERIFIED)
    return result, [
        GateResult(
            "deploy_attestation",
            True,
            "operator-attested record accepted by the validator (not independently verified)",
        ),
        GateResult(
            "pin_outcome",
            pin_go,
            f"recorded as {result.pin.outcome}"
            if pin_go
            else f"recorded as {DIFFERENCE}",
        ),
    ]


def _provider_attestation_present(root: Path) -> bool:
    """A real provider attestation. A local-cap record is not one and never counts here."""
    data = load_mapping(root / "config/spend_limits.yaml")
    items: Any = data.get("attestations") if data is not None else None
    return isinstance(items, list) and bool(items)


def _local_caps_enforced(root: Path) -> str | None:
    """The same enforcement check the live runtime uses. A label is not enough."""
    return local_caps_problem(root, today=date.today())


def _spend_limits(root: Path) -> GateResult:
    if _provider_attestation_present(root):
        return GateResult(
            "spend_limits_attested",
            True,
            "config/spend_limits.yaml holds an attestation (Gate F)",
        )
    problem = _local_caps_enforced(root)
    if problem is None:
        return GateResult(
            "spend_limits_attested",
            True,
            "local caps enforced: $5 run/day and $12 lifetime; not a provider limit, R8 and E-6 stay open",
        )
    return GateResult(
        "spend_limits_attested",
        False,
        f"no provider attestation and local caps are not enforced ({problem})",
    )


def r8_level(root: Path, today: date) -> str:
    evidence = validate_evidence(load_mapping(root / PROVIDER_EVIDENCE), today=today)
    deviation = validate_deviation(load_mapping(root / PROVIDER_DEVIATION), today=today)
    return r8_status(
        evidence_valid=evidence.valid,
        attestation_committed=_provider_attestation_present(root),
        deviation_valid=deviation.valid,
    )


def _provider_cap(root: Path, today: date) -> GateResult:
    evidence = validate_evidence(load_mapping(root / PROVIDER_EVIDENCE), today=today)
    if evidence.valid:
        return GateResult(
            "provider_cap",
            True,
            "named-human evidence accepted by the validator (attested, not verified)",
        )
    deviation = validate_deviation(load_mapping(root / PROVIDER_DEVIATION), today=today)
    if deviation.valid:
        return GateResult(
            "provider_cap",
            True,
            "written in-repo-caps-only deviation: R8 stays blocked and E-6 stays a gap",
        )
    return GateResult(
        "provider_cap",
        False,
        "no valid provider-cap evidence or deviation (Gate D not done)",
    )


def _public_target_approval(root: Path, today: date) -> GateResult:
    try:
        source = (root / "src/agentforge/safety/operator_approval.py").read_text(
            encoding="utf-8"
        )
    except OSError:
        return GateResult(
            "public_target_approval", False, "operator_approval.py is unreadable"
        )
    if "public-target" not in source:
        return GateResult(
            "public_target_approval",
            False,
            "the public-target approval scope is not implemented",
        )
    data = load_mapping(root / "config/operator_approval.yaml")
    items: Any = data.get("approvals") if data is not None else None
    if isinstance(items, list):
        for item in items:
            if not isinstance(item, dict) or item.get("scope") != "public-target":
                continue
            approved = parse_date(item.get("approved_on"))
            if (
                approved is not None
                and 0 <= (today - approved).days <= 1
                and item.get("purpose")
            ):
                return GateResult(
                    "public_target_approval",
                    True,
                    "a fresh public-target approval exists (at most 24 hours)",
                )
    return GateResult(
        "public_target_approval", False, "no fresh public-target approval record"
    )


def _k1(root: Path) -> GateResult:
    record = read_record(root / PUBLIC_TARGET_RECORD)
    if record is None:
        return GateResult(
            "k1_available",
            False,
            "K1 is unavailable: public-target authorization is not implemented and approved",
        )
    commit = record.get("implemented_commit", "")
    if (
        record.get("status") == "closed"
        and _COMMIT.match(commit)
        and record.get("approved_by")
    ):
        return GateResult(
            "k1_available",
            True,
            "public-target authorization is recorded as implemented and approved",
        )
    return GateResult(
        "k1_available",
        False,
        "K1 is unavailable: the public-target authorization record is not closed",
    )


def _p_u(root: Path) -> GateResult:
    record = read_record(root / P_U_RECORD)
    if record is None:
        return GateResult(
            "p_u_closed",
            False,
            "P-U record is missing, so the post-dispatch undercount is open",
        )
    if record.get("status") != "closed":
        return GateResult(
            "p_u_closed", False, "P-U is open: no billable live campaign may start"
        )
    if (
        not record.get("closing_test")
        or not _COMMIT.match(record.get("closing_commit", ""))
        or not record.get("approved_by")
    ):
        return GateResult(
            "p_u_closed",
            False,
            "P-U says closed but cites no closing test, commit and approver",
        )
    return GateResult("p_u_closed", True, "P-U is closed with a cited test and commit")


def _ceiling(root: Path, today: date, request_usd: Decimal) -> GateResult:
    exposure, problems = load_exposure(root / SPEND_RECONCILIATION, today=today)
    if exposure is None:
        return GateResult("lifetime_ceiling", False, "; ".join(problems))
    admission = admit(exposure, request_usd)
    if admission.allowed:
        detail = f"I + O + X + r is {admission.total_after}, within the ceiling"
        if admission.notices:
            detail += "; " + "; ".join(admission.notices)
        return GateResult("lifetime_ceiling", True, detail)
    return GateResult("lifetime_ceiling", False, "; ".join(admission.blocking))


def run_preflight(
    root: Path, *, today: date, request_usd: Decimal = Decimal("0")
) -> list[GateResult]:
    manifest, _ = load_manifest(root / "config/target_pin.yaml")
    attestation, deploy_gates = _deploy(root, manifest)
    origin: str | None = None
    if attestation is not None and attestation.valid:
        record = load_mapping(root / DEPLOY_ATTESTATION)
        origin = str(record.get("origin")) if record is not None else None
    current = _current_origin(root, manifest, today)
    if current is not None:
        origin = current
    return [
        _flags_false(root),
        _allowlist(root, origin),
        *deploy_gates,
        _provider_cap(root, today),
        _spend_limits(root),
        _public_target_approval(root, today),
        _k1(root),
        _p_u(root),
        _ceiling(root, today, request_usd),
    ]


__all__ = [
    "ACCEPTED",
    "BLOCKED",
    "BLOCKED_DEVIATION",
    "GateResult",
    "r8_level",
    "read_record",
    "run_preflight",
]
