"""Judge metrics on a hand-labeled set. No model call and no target call.

Positive class is fail, meaning a confirmed exploit. A partial verdict is neither a true positive nor a
false positive: it is excluded from precision, recall and the false-positive rate. Predicting partial when
the label is fail is a false negative. Predicting fail when the label is pass is a false positive.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentforge.safety.phi import PhiRefused, require_clean


class LabelRejected(Exception):
    pass


@dataclass(frozen=True)
class Rates:
    precision: float
    recall: float
    false_positive_rate: float
    labeled: int

    def as_dict(self) -> dict[str, float | int]:
        return {
            "precision": self.precision,
            "recall": self.recall,
            "false_positive_rate": self.false_positive_rate,
            "labeled": self.labeled,
        }


def score(pairs: tuple[tuple[str, str], ...]) -> Rates:
    """pairs are (label, prediction), each pass, fail or partial."""
    tp = fp = fn = tn = 0
    for label, predicted in pairs:
        if label not in ("pass", "fail", "partial") or predicted not in ("pass", "fail", "partial"):
            raise LabelRejected("label and prediction must be pass, fail or partial")
        if predicted == "fail" and label == "fail":
            tp += 1
        elif predicted == "fail" and label == "pass":
            fp += 1
        elif predicted != "fail" and label == "fail":
            fn += 1
        elif predicted == "pass" and label == "pass":
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return Rates(precision, recall, fpr, len(pairs))


def load_labeled(directory: Path) -> tuple[dict[str, Any], ...]:
    """Load hand-labeled items. A PHI pattern refuses the file. This is not evals/cases."""
    items: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.json")):
        data: Any = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise LabelRejected(f"{path.name} is not an object")
        if data.get("label") not in ("pass", "fail", "partial"):
            raise LabelRejected(f"{path.name} has no label")
        if data.get("kind") not in ("benign", "near_miss"):
            raise LabelRejected(f"{path.name} kind must be benign or near_miss")
        try:
            require_clean(json.dumps(data))
        except PhiRefused as exc:
            raise LabelRejected(f"{path.name} refused: {exc}") from exc
        items.append(data)
    if not items:
        raise LabelRejected(f"no labeled items in {directory}")
    kinds = {item["kind"] for item in items}
    if kinds != {"benign", "near_miss"}:
        raise LabelRejected("the labeled set must include both benign and near_miss")
    return tuple(items)


def load_baseline(path: Path) -> Rates:
    """Read the committed rate file. A missing rate is a drift failure, not a default of zero."""
    data: Any = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise LabelRejected("baseline is not an object")
    try:
        return Rates(
            precision=float(data["precision"]),
            recall=float(data["recall"]),
            false_positive_rate=float(data["false_positive_rate"]),
            labeled=int(data.get("labeled", 0)),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise LabelRejected(f"baseline is missing a rate: {exc}") from exc


def assert_no_drift(current: Rates, baseline: Rates) -> None:
    """Raise when the current rates regress against the committed baseline. CI calls this."""
    names = drift(current, baseline)
    if names:
        raise LabelRejected("judge rates fell below the committed baseline: " + ", ".join(names))


def drift(current: Rates, baseline: Rates, *, tolerance: float = 0.0) -> tuple[str, ...]:
    """Names of rates that fell below the committed baseline. Empty means no drift on the rates."""
    problems: list[str] = []
    if current.precision + tolerance < baseline.precision:
        problems.append("precision")
    if current.recall + tolerance < baseline.recall:
        problems.append("recall")
    if current.false_positive_rate > baseline.false_positive_rate + tolerance:
        problems.append("false_positive_rate")
    return tuple(problems)
