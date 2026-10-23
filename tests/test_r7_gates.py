"""R7-R8 gate validators and the offline preflight. Pure functions over made-up records. No network, no key."""

from __future__ import annotations

import copy
import io
import subprocess
from contextlib import contextmanager, redirect_stdout
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
import yaml
from r7_support import (
    ROOT,
    TODAY,
    attestation_record,
    build_green_root,
    evidence_record,
    real_manifest,
    reconciliation_record,
)

from agentforge.gates.attestation import validate_attestation
from agentforge.gates.ceiling import CEILING_USD, Exposure, admit, exposure_from_record
from agentforge.gates.common import is_blank, secret_problems, to_decimal
from agentforge.gates.pin import CONSISTENT, DIFFERENCE, UNVERIFIED, compare_observed, load_manifest
from agentforge.gates.preflight import r8_level, run_preflight
from agentforge.gates.provider_cap import (
    ACCEPTED,
    BLOCKED,
    BLOCKED_DEVIATION,
    r8_status,
    validate_deviation,
    validate_evidence,
)

ATTEST_DIR = ROOT / "Docs" / "attestations"
TEMPLATES = {
    "deploy-attestation.template.yaml",
    "provider-cap-evidence.template.yaml",
    "provider-cap-deviation.template.yaml",
    "spend-reconciliation.template.yaml",
}


def load(name: str) -> dict[str, Any]:
    data = yaml.safe_load((ATTEST_DIR / name).read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def gate(results: list[Any], name: str) -> Any:
    return next(item for item in results if item.name == name)


# Files a clean checkout does not have. Hiding them makes the real-repo assertions match CI.
_UNTRACKED_GATE_INPUTS = (
    ROOT / "config" / "allowlist.local.yaml",
    ROOT / "config" / "operator_approval.yaml",
    ROOT / "Docs/attestations/current-origin.yaml",
    ROOT / "Docs/attestations/deploy-attestation.yaml",
    ROOT / "Docs/attestations/provider-cap-deviation.yaml",
    ROOT / "Docs/attestations/provider-cap-evidence.yaml",
    ROOT / "Docs/attestations/spend-reconciliation.yaml",
)


@contextmanager
def _committed_gate_inputs(tmp_path: Path):  # type: ignore[no-untyped-def]
    """Hide untracked gate inputs, then restore them. Tracked files stay in place."""
    hidden: list[tuple[Path, Path]] = []
    for source in _UNTRACKED_GATE_INPUTS:
        tracked = subprocess.run(
            ["git", "ls-files", "--error-unmatch", "--", str(source.relative_to(ROOT))],
            cwd=ROOT,
            capture_output=True,
            check=False,
        )
        if tracked.returncode == 0 or not source.exists():
            continue
        destination = tmp_path / source.name
        if destination.exists():
            destination = tmp_path / f"{source.parent.name}-{source.name}"
        source.rename(destination)
        hidden.append((source, destination))
    try:
        yield
    finally:
        for source, destination in hidden:
            if destination.exists() and not source.exists():
                source.parent.mkdir(parents=True, exist_ok=True)
                destination.rename(source)


# --- manifest and pin outcome ---------------------------------------------------------------------------------
def test_the_shipped_manifest_loads_and_has_four_assets_and_three_controls() -> None:
    manifest = real_manifest()
    assert manifest.commit == "9f036541cf95e896db065e0c652afb75627b03c2"
    assert len(manifest.assets) == 4 and len(manifest.negative_controls) == 3


def test_a_bad_manifest_never_loads(tmp_path: Path) -> None:
    path = tmp_path / "m.yaml"
    path.write_text("pin: {commit: nothex, tree: nothex}\nassets: []\nnegative_controls: []\n")
    manifest, problems = load_manifest(path)
    assert manifest is None and len(problems) >= 3
    assert load_manifest(tmp_path / "missing.yaml")[0] is None


def _observed() -> dict[str, Any]:
    manifest = real_manifest()
    return copy.deepcopy(attestation_record(manifest)["observed"])


def test_full_matching_observation_is_consistent_never_verified() -> None:
    report = compare_observed(real_manifest(), _observed())
    assert report.outcome == CONSISTENT and "verified" not in report.outcome.replace("consistent", "")


def test_a_changed_asset_hash_is_a_difference() -> None:
    observed = _observed()
    first = next(iter(observed["assets"]))
    observed["assets"][first] = "0" * 64
    assert compare_observed(real_manifest(), observed).outcome == DIFFERENCE


def test_a_verified_source_path_deny_403_is_protected_not_a_blanket_403() -> None:
    observed = _observed()
    source = "src/StubRouteGuard.php"
    public = "public/stub_preflight.php"
    observed["negative_controls"][source] = 403
    assert compare_observed(real_manifest(), observed).outcome == DIFFERENCE
    observed["source_deny_verified"] = "module_source_deny"
    assert compare_observed(real_manifest(), observed).outcome == CONSISTENT
    observed["negative_controls"][public] = 403
    assert compare_observed(real_manifest(), observed).outcome == DIFFERENCE
    observed["negative_controls"][public] = 404
    observed["source_deny_verified"] = "some-other-403"
    observed["negative_controls"][source] = 403
    assert compare_observed(real_manifest(), observed).outcome == DIFFERENCE


@pytest.mark.parametrize("status", [200, 401, 403, 405])
def test_a_served_negative_control_is_a_difference(status: int) -> None:
    observed = _observed()
    first = next(iter(observed["negative_controls"]))
    observed["negative_controls"][first] = status
    assert compare_observed(real_manifest(), observed).outcome == DIFFERENCE


@pytest.mark.parametrize("status", [500, 502, 429, "404", True, None])
def test_an_unreadable_or_unclear_status_is_unverified(status: object) -> None:
    observed = _observed()
    first = next(iter(observed["negative_controls"]))
    observed["negative_controls"][first] = status
    assert compare_observed(real_manifest(), observed).outcome == UNVERIFIED


@pytest.mark.parametrize("observed", [None, {}, "x", {"assets": {}, "negative_controls": {}}])
def test_missing_observation_is_unverified(observed: object) -> None:
    assert compare_observed(real_manifest(), observed).outcome == UNVERIFIED


# --- attestation ----------------------------------------------------------------------------------------------
def _validate(record: dict[str, Any] | None) -> Any:
    return validate_attestation(record, real_manifest())


def test_a_complete_attestation_is_valid() -> None:
    result = _validate(attestation_record(real_manifest()))
    assert result.valid, result.problems
    assert result.pin is not None and result.pin.outcome == CONSISTENT


def test_the_unfilled_template_and_a_missing_record_are_rejected() -> None:
    assert not _validate(load("deploy-attestation.template.yaml")).valid
    assert not _validate(None).valid


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("attested_by_label", "verified"),
        ("operator", "TBD"),
        ("compose_project", "development-easy-light"),
        ("head_sha", "f" * 40),
        ("tree_sha", "f" * 40),
        ("git_status_porcelain_empty", False),
        ("image_ids", []),
        ("route", "live"),
        ("route_config_sha256", "not-a-hash"),
        ("security_gate_result", "fail"),
        ("agent_private_check", ""),
        ("fixture_credential_rotated", False),
        ("a001_confirmed", False),
        ("window_end_utc", "2026-10-22T13:00:00Z"),
        ("branch_protection", "maybe"),
        ("pin_outcome", "verified"),
        ("origin", "http://target.example"),
        ("origin", "https://localhost"),
        ("origin", "https://127.0.0.1"),
        ("origin", "https://203.0.113.5"),
        ("origin", "https://user:pw@target.example"),
        ("origin", "https://target.example:8443"),
        ("origin", "https://target.example/interface"),
        ("origin", ""),
        ("access_log_review", {"before": True, "after": False, "unexplained_entries": 0}),
        ("access_log_review", {"before": True, "after": True, "unexplained_entries": 2}),
    ],
)
def test_each_bad_attestation_field_is_rejected(field: str, value: Any) -> None:
    record = attestation_record(real_manifest())
    record[field] = value
    assert not _validate(record).valid, field


def test_declared_pin_outcome_must_match_the_computed_one() -> None:
    record = attestation_record(real_manifest())
    record["observed"]["negative_controls"] = {}
    assert not _validate(record).valid  # declared consistent, computed unverified
    record["pin_outcome"] = "unverified"
    assert _validate(record).valid


def test_a_pin_difference_blocks_the_attestation_even_when_declared_honestly() -> None:
    record = attestation_record(real_manifest())
    first = next(iter(record["observed"]["negative_controls"]))
    record["observed"]["negative_controls"][first] = 200
    record["pin_outcome"] = "difference"
    result = _validate(record)
    assert not result.valid and result.pin is not None and result.pin.outcome == DIFFERENCE


def test_a_credential_in_the_record_is_rejected() -> None:
    record = attestation_record(real_manifest())
    record["operator_password"] = "x"
    assert not _validate(record).valid
    record = attestation_record(real_manifest())
    record["seeded_data_source"] = "sk-" + "a1b2c3d4e5f6"
    assert not _validate(record).valid
    record = attestation_record(real_manifest())
    record["deploy_path"] = "Bearer abcdefghijkl"
    assert not _validate(record).valid


# --- provider cap ---------------------------------------------------------------------------------------------
def test_complete_evidence_is_valid_and_templates_are_not() -> None:
    assert validate_evidence(evidence_record(), today=TODAY).valid
    assert not validate_evidence(load("provider-cap-evidence.template.yaml"), today=TODAY).valid
    assert not validate_evidence(None, today=TODAY).valid


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("status", "verified"),
        ("provider", "other"),
        ("key_label", ""),
        ("method", "guess"),
        ("per_key_limit", False),
        ("limit_usd", 0),
        ("limit_usd", "abc"),
        ("usage_usd", 12),
        ("usage_usd", -1),
        ("limit_exceeded_already", True),
        ("observed_by", "TODO"),
        ("observed_on", "2026-09-01"),
        ("observed_on", "2026-12-01"),
        ("observed_on", "not-a-date"),
        ("reference", ""),
    ],
)
def test_each_bad_evidence_field_is_rejected(field: str, value: Any) -> None:
    record = evidence_record()
    record[field] = value
    assert not validate_evidence(record, today=TODAY).valid, field


def test_evidence_carrying_a_key_is_rejected() -> None:
    record = evidence_record()
    record["reference"] = "sk-" + "or-v1-abcdef123456"
    assert not validate_evidence(record, today=TODAY).valid


def test_local_caps_do_not_count_as_a_provider_attestation(tmp_path: Path) -> None:
    root = build_green_root(tmp_path)
    limits = root / "config/spend_limits.yaml"
    limits.write_text("attestations: []\n", encoding="utf-8")
    deviation = {
        "scope": "in-repo-caps-only",
        "approved_by": "Test Human",
        "approved_on": TODAY.isoformat(),
        "statement": "local caps only",
    }
    (root / "Docs/attestations/provider-cap-deviation.yaml").write_text(
        yaml.safe_dump(deviation), encoding="utf-8"
    )
    (root / "config/budget.yaml").write_text(
        "per_run_usd: 5.00\nper_day_usd: 5.00\nhard_ceiling_per_run_usd: 5.00\nhard_ceiling_per_day_usd: 15.00\n",
        encoding="utf-8",
    )
    (root / "src/agentforge/safety/ledger.py").write_text(
        "SHARED_CEILING_USD = 5.0\nif committed_usd(conn) > SHARED_CEILING_USD: raise BudgetExceeded\n",
        encoding="utf-8",
    )
    (root / "src/agentforge/safety/budget.py").write_text(
        "class BudgetExceeded(Exception):\n    pass\n\ndef reserve(self):\n    raise BudgetExceeded()\n",
        encoding="utf-8",
    )
    (root / "Docs/attestations/spend-reconciliation.yaml").write_text(
        yaml.safe_dump(reconciliation_record()), encoding="utf-8"
    )
    results = run_preflight(root, today=TODAY)
    assert gate(results, "spend_limits_attested").go
    assert "not a provider limit" in gate(results, "spend_limits_attested").reason
    assert r8_level(root, TODAY) == BLOCKED_DEVIATION
    limits.write_text(
        "local_cap_only: true\nattestations: []\n", encoding="utf-8"
    )
    (root / "src/agentforge/safety/ledger.py").write_text("SHARED_CEILING_USD = 50\n", encoding="utf-8")
    assert not gate(run_preflight(root, today=TODAY), "spend_limits_attested").go


def test_a_deviation_never_accepts_r8() -> None:
    good = {"scope": "in-repo-caps-only", "approved_by": "Test Human", "approved_on": "2026-10-21", "statement": "proceed"}
    assert validate_deviation(good, today=TODAY).valid
    assert not validate_deviation(load("provider-cap-deviation.template.yaml"), today=TODAY).valid
    assert r8_status(evidence_valid=False, attestation_committed=False, deviation_valid=True) == BLOCKED_DEVIATION
    assert r8_status(evidence_valid=False, attestation_committed=False, deviation_valid=False) == BLOCKED
    assert r8_status(evidence_valid=True, attestation_committed=False, deviation_valid=False) == BLOCKED
    assert r8_status(evidence_valid=True, attestation_committed=True, deviation_valid=True) == ACCEPTED


# --- the $12.00 lifetime ceiling ------------------------------------------------------------------------------
def test_exposure_is_incurred_plus_open_plus_excess_with_uncertain_inside_open() -> None:
    exposure, problems = exposure_from_record(
        reconciliation_record(incurred_usd=1, open_reserved_usd=2, uncertain_usd=0.5, excess_usd=0.25), today=TODAY
    )
    assert problems == [] and exposure is not None
    assert exposure.total == Decimal("3.25")  # 1 + 2 + 0.25. The 0.5 is inside the 2 and is not added again.


def test_uncertain_cannot_exceed_open_reservations() -> None:
    exposure, problems = exposure_from_record(reconciliation_record(open_reserved_usd=1, uncertain_usd=2), today=TODAY)
    assert exposure is None and problems


@pytest.mark.parametrize("field", ["incurred_usd", "open_reserved_usd", "uncertain_usd", "excess_usd"])
@pytest.mark.parametrize("value", [None, -1, "abc", True, float("nan")])
def test_bad_amounts_are_unusable(field: str, value: Any) -> None:
    exposure, problems = exposure_from_record(reconciliation_record(**{field: value}), today=TODAY)
    assert exposure is None and problems


def test_stale_future_and_missing_reconciliation_is_unusable() -> None:
    assert exposure_from_record(reconciliation_record(as_of="2026-10-20"), today=TODAY)[0] is None
    assert exposure_from_record(reconciliation_record(as_of="2026-10-23"), today=TODAY)[0] is None
    assert exposure_from_record(None, today=TODAY)[0] is None
    assert exposure_from_record(load("spend-reconciliation.template.yaml"), today=TODAY)[0] is None


def test_admission_is_at_most_twelve_dollars_inclusive() -> None:
    exposure = Exposure(Decimal("11.00"), Decimal("0"), Decimal("0"), Decimal("0"))
    assert admit(exposure, Decimal("1.00")).allowed
    assert not admit(exposure, Decimal("1.01")).allowed
    assert CEILING_USD == Decimal("12.00")


def test_excess_and_open_reservations_count_against_the_ceiling() -> None:
    exposure = Exposure(Decimal("5"), Decimal("5"), Decimal("0"), Decimal("1.5"))
    assert not admit(exposure, Decimal("1")).allowed
    assert admit(exposure, Decimal("0.5")).allowed


def test_a_breached_ceiling_halts_everything_even_a_free_request() -> None:
    exposure = Exposure(Decimal("12.01"), Decimal("0"), Decimal("0"), Decimal("0"))
    assert not admit(exposure, Decimal("0")).allowed


def test_uncertain_outcomes_are_flagged_for_every_approval_request_but_do_not_block_alone() -> None:
    exposure = Exposure(Decimal("1"), Decimal("0.05"), Decimal("0.05"), Decimal("0"))
    admission = admit(exposure, Decimal("0.05"))
    assert admission.allowed and admission.blocking == ()
    assert admission.uncertain_usd == Decimal("0.05") and len(admission.notices) == 1


def test_planned_reservations_stop_at_ten_dollars_thirty_five() -> None:
    exposure = Exposure(Decimal("0.15"), Decimal("0"), Decimal("0"), Decimal("0"))
    assert admit(exposure, Decimal("0.05"), planned_cumulative_usd=Decimal("10.30")).allowed
    assert not admit(exposure, Decimal("0.06"), planned_cumulative_usd=Decimal("10.30")).allowed


# --- helpers --------------------------------------------------------------------------------------------------
def test_common_helpers() -> None:
    assert is_blank(None) and is_blank(" TBD ") and not is_blank("x") and not is_blank(0)
    assert to_decimal("1.5") == Decimal("1.5") and to_decimal(True) is None and to_decimal(-1) is None
    assert secret_problems({"api_key": "x"}, "r") and not secret_problems({"label": "x"}, "r")


def test_every_shipped_template_exists() -> None:
    assert {p.name for p in ATTEST_DIR.glob("*.template.*")} >= TEMPLATES | {"log-access-inventory.template.md"}


# --- preflight ------------------------------------------------------------------------------------------------
def test_preflight_is_no_go_on_the_real_repo(tmp_path: Path) -> None:
    with _committed_gate_inputs(tmp_path):
        dated = ROOT / "Docs/attestations/spend-reconciliation.yaml"
        dated.write_text(
            "as_of: 2026-10-22\nincurred_usd: 0\nopen_reserved_usd: 0\nuncertain_usd: 0\nexcess_usd: 0\n",
            encoding="utf-8",
        )
        try:
            results = run_preflight(ROOT, today=TODAY)
            level = r8_level(ROOT, TODAY)
        finally:
            dated.unlink(missing_ok=True)
    assert not all(item.go for item in results)
    assert gate(results, "flags_false").go
    for name in (
        "allowlist_single_origin",
        "public_target_approval",
        "deploy_attestation",
        "pin_outcome",
        "provider_cap",
        "spend_limits_attested",
    ):
        assert not gate(results, name).go, name
    for name in ("lifetime_ceiling", "k1_available", "p_u_closed"):
        assert gate(results, name).go, name
    assert level == BLOCKED


def test_preflight_is_go_only_on_a_synthetic_all_green_root(tmp_path: Path) -> None:
    results = run_preflight(build_green_root(tmp_path), today=TODAY)
    assert all(item.go for item in results), [(i.name, i.reason) for i in results if not i.go]
    assert r8_level(build_green_root(tmp_path / "again"), TODAY) == ACCEPTED


def test_p_u_open_keeps_preflight_no_go(tmp_path: Path) -> None:
    root = build_green_root(tmp_path)
    (root / "Docs/prerequisites/P-U.md").write_text("status: open\n")
    results = run_preflight(root, today=TODAY)
    assert not gate(results, "p_u_closed").go
    assert all(item.go for item in results if item.name != "p_u_closed")


def test_a_p_u_closed_claim_without_evidence_is_still_no_go(tmp_path: Path) -> None:
    root = build_green_root(tmp_path)
    (root / "Docs/prerequisites/P-U.md").write_text("status: closed\n")
    assert not gate(run_preflight(root, today=TODAY), "p_u_closed").go


def test_k1_prerequisites_absent_keeps_k1_unavailable(tmp_path: Path) -> None:
    root = build_green_root(tmp_path)
    (root / "Docs/prerequisites/public-target-authorization.md").unlink()
    assert not gate(run_preflight(root, today=TODAY), "k1_available").go
    (root / "Docs/prerequisites/public-target-authorization.md").write_text("status: open\n")
    assert not gate(run_preflight(root, today=TODAY), "k1_available").go


def test_public_target_scope_missing_from_the_code_keeps_the_approval_gate_no_go(tmp_path: Path) -> None:
    root = build_green_root(tmp_path)
    (root / "src/agentforge/safety/operator_approval.py").write_text('SCOPES = frozenset({"local-target"})\n')
    assert not gate(run_preflight(root, today=TODAY), "public_target_approval").go


def test_a_stale_public_target_approval_is_no_go(tmp_path: Path) -> None:
    root = build_green_root(tmp_path)
    path = root / "config/operator_approval.yaml"
    data = yaml.safe_load(path.read_text())
    data["approvals"][0]["approved_on"] = "2026-10-19"
    path.write_text(yaml.safe_dump(data))
    assert not gate(run_preflight(root, today=TODAY), "public_target_approval").go


def test_ceiling_breach_is_no_go(tmp_path: Path) -> None:
    root = build_green_root(tmp_path)
    path = root / "Docs/attestations/spend-reconciliation.yaml"
    path.write_text(yaml.safe_dump(reconciliation_record(incurred_usd=11.9)))
    assert gate(run_preflight(root, today=TODAY, request_usd=Decimal("0.1")), "lifetime_ceiling").go
    assert not gate(run_preflight(root, today=TODAY, request_usd=Decimal("0.2")), "lifetime_ceiling").go


def test_flags_true_in_the_committed_file_is_no_go(tmp_path: Path) -> None:
    root = build_green_root(tmp_path)
    (root / "src/agentforge/safety/chokepoint.py").write_text("LIVE_ENABLED = True\nPROVIDER_ENABLED = False\n")
    assert not gate(run_preflight(root, today=TODAY), "flags_false").go


@pytest.mark.parametrize(
    "entries",
    [
        [],
        [{"scheme": "http", "host": "target.example", "port": 80, "path_prefix": "/interface"}],
        [{"scheme": "https", "host": "target.example", "port": 443, "path_prefix": "/"}],
        [
            {"scheme": "https", "host": "target.example", "port": 443, "path_prefix": "/interface"},
            {"scheme": "https", "host": "target.example", "port": 443, "path_prefix": "/library/ajax"},
            {"scheme": "https", "host": "target.example", "port": 443, "path_prefix": "/admin"},
        ],
        [
            {"scheme": "https", "host": "target.example", "port": 443, "path_prefix": "/interface"},
            {"scheme": "https", "host": "target.example", "port": 443, "path_prefix": "/library/ajax"},
            {"scheme": "https", "host": "other.example", "port": 443, "path_prefix": "/interface"},
        ],
        [
            {"scheme": "https", "host": "other.example", "port": 443, "path_prefix": "/interface"},
            {"scheme": "https", "host": "other.example", "port": 443, "path_prefix": "/library/ajax"},
        ],
    ],
)
def test_allowlist_gate_rejects_every_wrong_shape(tmp_path: Path, entries: list[dict[str, Any]]) -> None:
    root = build_green_root(tmp_path)
    (root / "config/allowlist.yaml").write_text(yaml.safe_dump({"entries": entries}))
    assert not gate(run_preflight(root, today=TODAY), "allowlist_single_origin").go


def test_a_verified_current_origin_binds_without_rewriting_the_closed_attestation(tmp_path: Path) -> None:
    root = build_green_root(tmp_path)
    closed = yaml.safe_load((root / "Docs/attestations/deploy-attestation.yaml").read_text())
    historical = closed["origin"]
    (root / "config/allowlist.yaml").write_text(
        yaml.safe_dump(
            {
                "entries": [
                    {"scheme": "https", "host": "later.example", "port": 443, "path_prefix": "/interface"},
                    {"scheme": "https", "host": "later.example", "port": 443, "path_prefix": "/library/ajax"},
                ]
            }
        ),
        encoding="utf-8",
    )
    approval = yaml.safe_load((root / "config/operator_approval.yaml").read_text())
    approval["approvals"][0]["origin"] = "https://later.example"
    (root / "config/operator_approval.yaml").write_text(yaml.safe_dump(approval), encoding="utf-8")
    current = {
        "status": "verified",
        "origin": "https://later.example",
        "head_sha": closed["head_sha"],
        "tree_sha": closed["tree_sha"],
        "observed": closed["observed"],
    }
    (root / "Docs/attestations/current-origin.yaml").write_text(yaml.safe_dump(current), encoding="utf-8")
    assert gate(run_preflight(root, today=TODAY), "allowlist_single_origin").go
    assert yaml.safe_load((root / "Docs/attestations/deploy-attestation.yaml").read_text())["origin"] == historical
    current["status"] = "unverified"
    (root / "Docs/attestations/current-origin.yaml").write_text(yaml.safe_dump(current), encoding="utf-8")
    assert not gate(run_preflight(root, today=TODAY), "allowlist_single_origin").go


def test_the_preflight_script_exits_non_zero_on_the_real_repo_and_zero_on_green(tmp_path: Path) -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location("preflight_live_under_test", ROOT / "scripts" / "preflight_live.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    out = io.StringIO()
    with _committed_gate_inputs(tmp_path):
        with redirect_stdout(out):
            assert module.main(["--root", str(ROOT)]) == 1
    assert "PREFLIGHT: NO-GO" in out.getvalue()
    assert module.main(["--request-usd", "abc"]) == 2
    assert module.main(["--request-usd", "-1"]) == 2


# --- regression: IP-literal origins, structured admission, rename ----------------------------------------------
@pytest.mark.parametrize(
    "origin",
    [
        "https://[2001:db8::1]",
        "https://[::1]",
        "https://[::ffff:127.0.0.1]",
        "https://0x7f.1",
        "https://0x7f.0x0.0x0.0x1",
        "https://0177.0.0.1",
        "https://127.1",
        "https://2130706433",
        "https://203.0.113.5",
        "https://10.0.0.5",
        "https://0.0.0.0",
        "https://localhost",
        "https://intranet",
        "https://target.local",
        "https://target.internal",
        "https://app.localhost",
        "https://target.example.",
        "https://-bad.example",
        "https://under_score.example",
        "https://target.123",
    ],
)
def test_ip_literals_and_non_public_hosts_are_rejected_as_an_origin(origin: str) -> None:
    record = attestation_record(real_manifest())
    record["origin"] = origin
    result = _validate(record)
    assert not result.valid and any("origin" in problem for problem in result.problems), origin


@pytest.mark.parametrize("origin", ["https://target.example", "https://TARGET.Example:443", "https://a-b.c.example/", "https://xn--bcher-kva.example"])
def test_ordinary_public_hostnames_are_still_accepted(origin: str) -> None:
    record = attestation_record(real_manifest())
    record["origin"] = origin
    assert _validate(record).valid


def test_the_allowlist_gate_rejects_an_ip_literal_public_origin(tmp_path: Path) -> None:
    for host in ("203.0.113.5", "2001:db8::1", "0x7f.1", "10.0.0.5", "target.internal"):
        root = build_green_root(tmp_path / host.replace(":", "_"))
        entries = [
            {"scheme": "https", "host": host, "port": 443, "path_prefix": "/interface"},
            {"scheme": "https", "host": host, "port": 443, "path_prefix": "/library/ajax"},
        ]
        (root / "config/allowlist.yaml").write_text(yaml.safe_dump({"entries": entries}))
        result = gate(run_preflight(root, today=TODAY), "allowlist_single_origin")
        assert not result.go, host


def test_admission_separates_blocking_reasons_from_notices() -> None:
    uncertain = Exposure(Decimal("1"), Decimal("0.05"), Decimal("0.05"), Decimal("0"))
    ok = admit(uncertain, Decimal("0.05"))
    assert ok.allowed and ok.blocking == () and ok.notices and ok.reasons == ok.notices
    over = admit(Exposure(Decimal("11.99"), Decimal("0"), Decimal("0"), Decimal("0")), Decimal("0.05"))
    assert not over.allowed and over.blocking and over.notices == ()
    both = admit(Exposure(Decimal("12"), Decimal("0.05"), Decimal("0.05"), Decimal("0")), Decimal("0.05"))
    assert not both.allowed and both.blocking and both.notices and both.uncertain_usd == Decimal("0.05")


def test_a_notice_wording_change_cannot_change_the_decision() -> None:
    import dataclasses

    exposure = Exposure(Decimal("1"), Decimal("0.05"), Decimal("0.05"), Decimal("0"))
    admission = admit(exposure, Decimal("0.05"))
    reworded = dataclasses.replace(admission, notices=("something else entirely",))
    assert reworded.allowed == admission.allowed is True
    assert admit(Exposure(Decimal("12.5"), Decimal("0"), Decimal("0"), Decimal("0")), Decimal("0")).allowed is False


def test_preflight_ceiling_gate_is_go_with_an_uncertain_notice_and_says_so(tmp_path: Path) -> None:
    root = build_green_root(tmp_path)
    path = root / "Docs/attestations/spend-reconciliation.yaml"
    path.write_text(yaml.safe_dump(reconciliation_record(open_reserved_usd=0.05, uncertain_usd=0.05)))
    result = gate(run_preflight(root, today=TODAY), "lifetime_ceiling")
    assert result.go and "uncertain" in result.reason
