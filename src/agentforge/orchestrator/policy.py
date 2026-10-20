"""Orchestrator policy: config loading, bounded retry classification and the cost-aware stop rule.

Pure functions plus a validated config. Nothing here sends a request or touches the ledger. The clock and sleep are
injected by the caller. Config can only tighten limits: a value above a hard ceiling refuses to load.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

CONFIG_PATH = Path(__file__).resolve().parents[3] / "config" / "orchestrator.yaml"
HARD_MAX_TURNS = 4
HARD_MAX_VARIANTS = 10


class ConfigError(ValueError):
    """The orchestrator config is missing a value or is out of range. The run refuses to start."""


@dataclass(frozen=True)
class Weights:
    open_high_finding: int = 100
    regression_component: int = 60
    coverage_gap: int = 40
    low_pass_rate: int = 20
    low_pass_rate_below: float = 0.5


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts_per_step: int = 3
    max_attempts_per_campaign: int = 6
    base_delay_s: float = 1.0
    max_delay_s: float = 30.0


@dataclass(frozen=True)
class StopPolicy:
    after_attacks: int = 5
    spend_fraction: float = 0.25
    max_redirects: int = 1


@dataclass(frozen=True)
class Limits:
    max_sequences_per_campaign: int = 10
    max_turns: int = 3
    max_rejections: int = 2
    max_mutations_per_parent: int = 2
    max_mutation_depth: int = 2


@dataclass(frozen=True)
class VariantConfig:
    variants_requested: int = 10
    max_total_rejections: int = 10
    max_turns_per_variant: int = 1


@dataclass(frozen=True)
class Config:
    weights: Weights = field(default_factory=Weights)
    fallback_order: tuple[str, ...] = ("TM-PI", "TM-EX", "TM-DS", "TM-SC", "TM-TM", "TM-ID")
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    stop: StopPolicy = field(default_factory=StopPolicy)
    limits: Limits = field(default_factory=Limits)
    novelty_threshold: float = 0.35
    variants: VariantConfig = field(default_factory=VariantConfig)

    @property
    def max_turns_total(self) -> int:
        return self.limits.max_turns * self.limits.max_sequences_per_campaign


def _int(raw: Any, name: str, low: int, high: int) -> int:
    if isinstance(raw, bool) or not isinstance(raw, int) or not low <= raw <= high:
        raise ConfigError(f"{name} must be an integer from {low} to {high}")
    return int(raw)


def _num(raw: Any, name: str, low: float, high: float) -> float:
    if isinstance(raw, bool) or not isinstance(raw, (int, float)) or not low <= float(raw) <= high:
        raise ConfigError(f"{name} must be a number from {low} to {high}")
    return float(raw)


def validate_variants(requested: object) -> int:
    """1 to 10 only. A hard-coded ceiling of 10 cannot be raised by config or by a request."""
    return _int(requested, "variants_requested", 1, HARD_MAX_VARIANTS)


def parse_config(data: Any) -> Config:
    if not isinstance(data, dict):
        raise ConfigError("orchestrator config must be a mapping")
    try:
        w, r, s, lim, nov, var = (data[k] for k in ("weights", "retry", "stop", "limits", "novelty", "variant_campaign"))
        order = tuple(str(x) for x in data["fallback_order"])
        limits = Limits(
            max_sequences_per_campaign=_int(lim["max_sequences_per_campaign"], "max_sequences_per_campaign", 1, 50),
            max_turns=_int(lim["max_turns"], "max_turns", 1, HARD_MAX_TURNS),
            max_rejections=_int(lim["max_rejections"], "max_rejections", 0, 10),
            max_mutations_per_parent=_int(lim["max_mutations_per_parent"], "max_mutations_per_parent", 0, 10),
            max_mutation_depth=_int(lim["max_mutation_depth"], "max_mutation_depth", 0, 2),
        )
        variants = VariantConfig(
            variants_requested=validate_variants(var["variants_requested"]),
            max_total_rejections=_int(var["max_total_rejections"], "max_total_rejections", 0, 50),
            max_turns_per_variant=_int(var["max_turns_per_variant"], "max_turns_per_variant", 1, limits.max_turns),
        )
        return Config(
            weights=Weights(
                open_high_finding=_int(w["open_high_finding"], "open_high_finding", 0, 1000),
                regression_component=_int(w["regression_component"], "regression_component", 0, 1000),
                coverage_gap=_int(w["coverage_gap"], "coverage_gap", 0, 1000),
                low_pass_rate=_int(w["low_pass_rate"], "low_pass_rate", 0, 1000),
                low_pass_rate_below=_num(w["low_pass_rate_below"], "low_pass_rate_below", 0.0, 1.0),
            ),
            fallback_order=order,
            retry=RetryPolicy(
                max_attempts_per_step=_int(r["max_attempts_per_step"], "max_attempts_per_step", 1, 10),
                max_attempts_per_campaign=_int(r["max_attempts_per_campaign"], "max_attempts_per_campaign", 1, 50),
                base_delay_s=_num(r["base_delay_s"], "base_delay_s", 0.0, 3600.0),
                max_delay_s=_num(r["max_delay_s"], "max_delay_s", 0.0, 3600.0),
            ),
            stop=StopPolicy(
                after_attacks=_int(s["after_attacks"], "after_attacks", 1, 1000),
                spend_fraction=_num(s["spend_fraction"], "spend_fraction", 0.0, 1.0),
                max_redirects=_int(s["max_redirects"], "max_redirects", 0, 1),
            ),
            limits=limits,
            novelty_threshold=_num(nov["threshold"], "novelty threshold", 0.0, 1.0),
            variants=variants,
        )
    except KeyError as exc:
        raise ConfigError(f"orchestrator config is missing {exc}") from exc


def load_config(path: Path | None = None) -> Config:
    try:
        data = yaml.safe_load((path or CONFIG_PATH).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError("orchestrator config could not be read") from exc
    return parse_config(data)
