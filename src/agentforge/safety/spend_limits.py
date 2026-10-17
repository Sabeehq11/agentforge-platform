"""Provider-side spend-limit attestation gate.

The repo cannot verify a provider dashboard setting. This module only checks that a human recorded one, recently.
It queries no provider. A missing, malformed or stale record refuses live use.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import yaml


class SpendLimitNotAttested(Exception):
    pass


@dataclass(frozen=True)
class Attestation:
    provider: str
    key_label: str
    limit_usd: float
    attested_by: str
    attested_on: date


def load_attestations(path: str | Path) -> list[Attestation]:
    """Malformed or missing files yield no attestations, so live use stays refused."""
    try:
        data: Any = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return []
    if not isinstance(data, dict) or not isinstance(data.get("attestations"), list):
        return []
    out: list[Attestation] = []
    for raw in data["attestations"]:
        try:
            on = raw["attested_on"]
            if not isinstance(on, date):
                on = date.fromisoformat(str(on))
            limit = float(raw["limit_usd"])
            if limit <= 0:
                continue
            out.append(
                Attestation(
                    provider=str(raw["provider"]).lower(),
                    key_label=str(raw["key_label"]),
                    limit_usd=limit,
                    attested_by=str(raw["attested_by"]),
                    attested_on=on,
                )
            )
        except (KeyError, TypeError, ValueError):
            continue
    return out


def require_attested(
    provider: str,
    attestations: list[Attestation],
    *,
    today: date,
    max_age_days: int = 30,
) -> Attestation:
    """Return a fresh attestation for the provider or raise."""
    for a in attestations:
        if a.provider != provider.lower() or not a.attested_by.strip():
            continue
        age = today - a.attested_on
        if timedelta(0) <= age <= timedelta(days=max_age_days):
            return a
    raise SpendLimitNotAttested(f"no fresh provider-side spend-limit attestation for {provider!r}")
