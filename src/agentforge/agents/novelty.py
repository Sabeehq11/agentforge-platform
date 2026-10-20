"""Novelty measure. Diversity only: it never counts as security signal.

Text is normalized (lowercased, punctuation and whitespace collapsed, canary and fixture identifiers masked, the
seed's own text removed). Distance is 1 minus Jaccard similarity over character 3-grams and over word bigrams, and
the lower of the two is taken, so suffix padding, trailing space and case changes score as near-duplicates.
A multi-turn attack is compared as the joined turns and turn by turn, and the lowest distance wins, so a repeated
turn cannot inflate novelty.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

_MASK = re.compile(r"\b(?:canary|fixture|synthetic)[-_a-z0-9]*\b|\bcanary-[a-z0-9-]+\b", re.IGNORECASE)
_PUNCT = re.compile(r"[^a-z0-9]+")


def normalize(text: str, *, remove: Sequence[str] = ()) -> str:
    """Lowercase, mask identifiers, drop the seed's own text, collapse everything but letters and digits."""
    lowered = text.lower()
    for chunk in remove:
        piece = chunk.lower().strip()
        if piece:
            lowered = lowered.replace(piece, " ")
    masked = _MASK.sub(" ", lowered)
    return _PUNCT.sub(" ", masked).strip()


def _grams(text: str, n: int) -> set[str]:
    squeezed = text.replace(" ", "")
    return {squeezed[i : i + n] for i in range(len(squeezed) - n + 1)} if len(squeezed) >= n else {squeezed} if squeezed else set()


def _bigrams(text: str) -> set[str]:
    words = text.split()
    if len(words) < 2:
        return {" ".join(words)} if words else set()
    return {f"{words[i]} {words[i + 1]}" for i in range(len(words) - 1)}


def _distance_sets(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 0.0
    if not a or not b:
        return 1.0
    return 1.0 - len(a & b) / len(a | b)


def text_distance(a: str, b: str) -> float:
    """Lower of the character 3-gram and word-bigram distances, on already normalized text."""
    return min(_distance_sets(_grams(a, 3), _grams(b, 3)), _distance_sets(_bigrams(a), _bigrams(b)))


def sequence_distance(left: Sequence[str], right: Sequence[str], *, remove: Sequence[str] = ()) -> float:
    """Joined-sequence distance, and turn by turn, whichever is lowest. Empty text is a duplicate of anything empty."""
    nl = [normalize(t, remove=remove) for t in left]
    nr = [normalize(t, remove=remove) for t in right]
    best = text_distance(" ".join(nl), " ".join(nr))
    for x in nl:
        for y in nr:
            best = min(best, text_distance(x, y))
    return best


@dataclass
class NoveltyReport:
    threshold: float
    pairs: list[tuple[str, str, float]] = field(default_factory=list)
    rejected: list[tuple[str, str, float]] = field(default_factory=list)

    @property
    def minimum(self) -> float | None:
        return min((d for _a, _b, d in self.pairs), default=None)

    def as_dict(self) -> dict[str, object]:
        return {
            "threshold": self.threshold,
            "minimum_distance": self.minimum,
            "pair_count": len(self.pairs),
            "pairs": [{"a": a, "b": b, "distance": round(d, 4)} for a, b, d in self.pairs],
            "rejected": [{"a": a, "b": b, "distance": round(d, 4)} for a, b, d in self.rejected],
        }


def check_novel(
    candidate: Sequence[str],
    candidate_id: str,
    references: Iterable[tuple[str, Sequence[str]]],
    threshold: float,
    report: NoveltyReport | None = None,
    *,
    remove: Sequence[str] = (),
) -> tuple[bool, float | None]:
    """True when the candidate clears the threshold against every reference. Records each pair in the report.

    references are (id, turns): the parent, every seed, earlier accepted variants and persisted variants. When
    the candidate fails, the pairs are recorded in report.rejected and not in report.pairs.
    """
    measured = [(ref_id, sequence_distance(candidate, turns, remove=remove)) for ref_id, turns in references]
    lowest = min((d for _i, d in measured), default=None)
    if report is not None:
        if lowest is not None and lowest < threshold:
            worst = min(measured, key=lambda m: m[1])
            report.rejected.append((candidate_id, worst[0], worst[1]))
        else:
            report.pairs.extend((candidate_id, ref_id, d) for ref_id, d in measured)
    return (lowest is None or lowest >= threshold), lowest
