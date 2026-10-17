from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from agentforge.safety.spend_limits import SpendLimitNotAttested, load_attestations, require_attested

ROOT = Path(__file__).resolve().parents[1]
TODAY = date(2026, 10, 20)

GOOD = (
    "attestations:\n"
    "  - {provider: openrouter, key_label: k1, limit_usd: 10, attested_by: someone, attested_on: 2026-10-17}\n"
)


def write(tmp_path: Path, body: str) -> Path:
    f = tmp_path / "s.yaml"
    f.write_text(body)
    return f


def test_shipped_file_refuses() -> None:
    atts = load_attestations(ROOT / "config" / "spend_limits.yaml")
    assert atts == []
    with pytest.raises(SpendLimitNotAttested):
        require_attested("openrouter", atts, today=TODAY)


def test_missing_file_refuses(tmp_path: Path) -> None:
    with pytest.raises(SpendLimitNotAttested):
        require_attested("openrouter", load_attestations(tmp_path / "none.yaml"), today=TODAY)


def test_fresh_attestation_accepted(tmp_path: Path) -> None:
    a = require_attested("OpenRouter", load_attestations(write(tmp_path, GOOD)), today=TODAY)
    assert a.limit_usd == 10


def test_stale_attestation_refused(tmp_path: Path) -> None:
    atts = load_attestations(write(tmp_path, GOOD))
    with pytest.raises(SpendLimitNotAttested):
        require_attested("openrouter", atts, today=date(2026, 12, 25))


def test_future_dated_attestation_refused(tmp_path: Path) -> None:
    atts = load_attestations(write(tmp_path, GOOD))
    with pytest.raises(SpendLimitNotAttested):
        require_attested("openrouter", atts, today=date(2026, 10, 1))


def test_other_provider_refused(tmp_path: Path) -> None:
    atts = load_attestations(write(tmp_path, GOOD))
    with pytest.raises(SpendLimitNotAttested):
        require_attested("anthropic", atts, today=TODAY)


@pytest.mark.parametrize(
    "body",
    [
        "attestations:\n  - {provider: openrouter, key_label: k, limit_usd: 0, attested_by: x, attested_on: 2026-10-17}\n",
        "attestations:\n  - {provider: openrouter, key_label: k, limit_usd: 5, attested_by: '', attested_on: 2026-10-17}\n",
        "attestations:\n  - {provider: openrouter, key_label: k, limit_usd: 5, attested_by: x, attested_on: not-a-date}\n",
        "attestations:\n  - {provider: openrouter}\n",
        "attestations: nope\n",
        "{{{ bad",
    ],
)
def test_invalid_records_refuse(tmp_path: Path, body: str) -> None:
    with pytest.raises(SpendLimitNotAttested):
        require_attested("openrouter", load_attestations(write(tmp_path, body)), today=TODAY)
