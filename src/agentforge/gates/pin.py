"""Compare operator-observed values to the pin manifest (config/target_pin.yaml).

The outcome is one of `consistent_with_pin`, `difference` or `unverified`. It is never "verified": the agent code is
private and the module assets are identical in the dirty tree and at the pin, so an outside check can show a
difference but cannot prove a clean build. Nothing here makes a request. The observation is supplied by a human.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentforge.gates.common import is_hex40, is_hex64, load_mapping

CONSISTENT = "consistent_with_pin"
DIFFERENCE = "difference"
UNVERIFIED = "unverified"
OUTCOMES = frozenset({CONSISTENT, DIFFERENCE, UNVERIFIED})

# A missing file answers 404 at the pin. These statuses mean something is served at the path.
_PRESENT = frozenset({200, 401, 403, 405})
_ABSENT = frozenset({404})


@dataclass(frozen=True)
class Manifest:
    commit: str
    tree: str
    assets: dict[str, str]
    negative_controls: tuple[str, ...]


@dataclass(frozen=True)
class PinReport:
    outcome: str
    reasons: tuple[str, ...] = field(default_factory=tuple)


def load_manifest(path: Path) -> tuple[Manifest | None, list[str]]:
    """The manifest, or None with the reasons it is unusable. A bad manifest never yields a pass."""
    data = load_mapping(path)
    if data is None:
        return None, [f"manifest {path.name} is missing or unreadable"]
    problems: list[str] = []
    pin = data.get("pin")
    commit = pin.get("commit") if isinstance(pin, dict) else None
    tree = pin.get("tree") if isinstance(pin, dict) else None
    if not is_hex40(commit):
        problems.append("manifest pin.commit is not a 40-character lowercase hex sha")
    if not is_hex40(tree):
        problems.append("manifest pin.tree is not a 40-character lowercase hex sha")
    assets: dict[str, str] = {}
    raw_assets = data.get("assets")
    if not isinstance(raw_assets, list) or not raw_assets:
        problems.append("manifest assets must be a non-empty list")
    else:
        for item in raw_assets:
            asset_path = item.get("path") if isinstance(item, dict) else None
            digest = item.get("sha256") if isinstance(item, dict) else None
            if (
                not isinstance(asset_path, str)
                or not asset_path
                or not is_hex64(digest)
            ):
                problems.append(
                    "manifest asset needs a path and a 64-character lowercase sha256"
                )
                continue
            assets[asset_path] = str(digest)
    controls = data.get("negative_controls")
    if (
        not isinstance(controls, list)
        or not controls
        or not all(isinstance(c, str) and c for c in controls)
    ):
        problems.append("manifest negative_controls must be a non-empty list of paths")
    if problems:
        return None, problems
    assert isinstance(controls, list)
    return Manifest(str(commit), str(tree), assets, tuple(str(c) for c in controls)), []


def compare_observed(manifest: Manifest, observed: Any) -> PinReport:
    """Judge a human-supplied observation. Anything not shown to match is `unverified`, never a default pass.

    observed is a mapping with `assets` ({path: sha256}) and `negative_controls` ({path: http status}).
    A hash that differs, or a negative-control path that is served, is a `difference`. A missing item, an
    unreadable value or an unexpected status is `unverified`. Only a full, matching observation is consistent.
    """
    if not isinstance(observed, dict):
        return PinReport(UNVERIFIED, ("no observation was supplied",))
    differences: list[str] = []
    gaps: list[str] = []

    seen_assets = observed.get("assets")
    if not isinstance(seen_assets, dict):
        seen_assets = {}
        gaps.append("no asset hashes were observed")
    for path, expected in manifest.assets.items():
        value = seen_assets.get(path)
        if not is_hex64(value):
            gaps.append(f"asset {path} was not observed as a 64-character sha256")
        elif value != expected:
            differences.append(f"asset {path} differs from the pin")

    seen_controls = observed.get("negative_controls")
    if not isinstance(seen_controls, dict):
        seen_controls = {}
        gaps.append("no negative-control results were observed")
    for path in manifest.negative_controls:
        status = seen_controls.get(path)
        if isinstance(status, bool) or not isinstance(status, int):
            gaps.append(f"negative control {path} was not observed as an HTTP status")
        elif status in _PRESENT:
            differences.append(
                f"negative control {path} is served (status {status}) but is absent at the pin"
            )
        elif status not in _ABSENT:
            gaps.append(
                f"negative control {path} gave status {status}, which neither shows nor rules out the file"
            )

    if differences:
        return PinReport(DIFFERENCE, tuple(differences + gaps))
    if gaps:
        return PinReport(UNVERIFIED, tuple(gaps))
    return PinReport(
        CONSISTENT,
        ("every observed asset matches and every negative control is absent",),
    )
