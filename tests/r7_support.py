"""Synthetic fixtures for the R7-R8 gate tests. Every value is made up. Nothing here reads a secret or a real file
outside a temporary directory, except config/target_pin.yaml, which is reviewed config."""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Any

import yaml

from agentforge.gates.pin import Manifest, load_manifest

ROOT = Path(__file__).resolve().parents[1]
TODAY = date(2026, 10, 22)
ORIGIN = "https://target.example"


def real_manifest() -> Manifest:
    manifest, problems = load_manifest(ROOT / "config" / "target_pin.yaml")
    assert manifest is not None, problems
    return manifest


def attestation_record(manifest: Manifest) -> dict[str, Any]:
    return {
        "attested_by_label": "operator-attested",
        "operator": "Test Operator",
        "window_start_utc": "2026-10-22T14:00:00Z",
        "window_end_utc": "2026-10-22T16:00:00Z",
        "deploy_path": "/srv/pin-checkout",
        "compose_project": "pin-public",
        "head_sha": manifest.commit,
        "tree_sha": manifest.tree,
        "git_status_porcelain_empty": True,
        "image_ids": ["sha256:" + "a" * 64],
        "route": "stub",
        "route_config_sha256": "b" * 64,
        "security_gate_result": "pass",
        "agent_private_check": "pass",
        "fixture_credential_rotated": True,
        "seeded_data_source": "synthetic seed script",
        "a001_confirmed": True,
        "origin": ORIGIN,
        "access_log_review": {"before": True, "after": True, "unexplained_entries": 0},
        "branch_protection": "unchecked",
        "pin_outcome": "consistent_with_pin",
        "observed": {
            "assets": dict(manifest.assets),
            "negative_controls": {path: 404 for path in manifest.negative_controls},
        },
    }


def evidence_record() -> dict[str, Any]:
    return {
        "status": "attested_not_verified",
        "provider": "openrouter",
        "key_label": "shared-key-label",
        "method": "dashboard",
        "per_key_limit": True,
        "limit_usd": 12,
        "usage_usd": 3,
        "limit_exceeded_already": False,
        "observed_by": "Test Human",
        "observed_on": "2026-10-21",
        "reference": "screenshot-001",
    }


def reconciliation_record(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "as_of": "2026-10-22",
        "incurred_usd": 0.1522038,
        "open_reserved_usd": 0,
        "uncertain_usd": 0,
        "excess_usd": 0,
        "notes": "synthetic",
    }
    base.update(over)
    return base


def _write_yaml(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data), encoding="utf-8")


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def build_green_root(tmp_path: Path) -> Path:
    """A synthetic repo root in which every preflight gate is GO. The real repo is never all green."""
    manifest = real_manifest()
    root = tmp_path / "green"
    _write(
        root / "src/agentforge/safety/chokepoint.py",
        "LIVE_ENABLED = False\nPROVIDER_ENABLED = False\n",
    )
    _write(
        root / "src/agentforge/safety/operator_approval.py",
        'SCOPES = frozenset({"local-target", "openrouter", "public-target"})\n',
    )
    _write(root / "config/target_pin.yaml", (ROOT / "config/target_pin.yaml").read_text(encoding="utf-8"))
    host = "target.example"
    _write_yaml(
        root / "config/allowlist.yaml",
        {
            "entries": [
                {"scheme": "http", "host": "127.0.0.1", "port": 8300, "path_prefix": "/"},
                {"scheme": "https", "host": host, "port": 443, "path_prefix": "/interface"},
                {"scheme": "https", "host": host, "port": 443, "path_prefix": "/library/ajax"},
            ]
        },
    )
    _write_yaml(
        root / "config/spend_limits.yaml",
        {"attestations": [{"provider": "openrouter", "key_label": "k", "limit_usd": 12, "attested_by": "x", "attested_on": "2026-10-21"}]},
    )
    _write_yaml(
        root / "config/operator_approval.yaml",
        {
            "approvals": [
                {"approved_by": "x", "approved_on": "2026-10-22", "scope": "public-target", "max_usd": 0, "purpose": "synthetic", "origin": "https://target.example"}
            ]
        },
    )
    _write_yaml(root / "Docs/attestations/deploy-attestation.yaml", attestation_record(manifest))
    _write_yaml(root / "Docs/attestations/provider-cap-evidence.yaml", evidence_record())
    _write_yaml(root / "Docs/attestations/spend-reconciliation.yaml", reconciliation_record())
    _write(
        root / "Docs/prerequisites/P-U.md",
        "status: closed\nclosing_test: tests/test_p_u.py::test_closed\nclosing_commit: abcdef1\napproved_by: Test Human\n",
    )
    _write(
        root / "Docs/prerequisites/public-target-authorization.md",
        "status: closed\nimplemented_commit: abcdef2\napproved_by: Test Human\n",
    )
    return root
