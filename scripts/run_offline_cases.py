#!/usr/bin/env python3
"""Grade the offline safe and weakened pairs and write evals/results/offline-latest.json.

No network, no model call, no target. The output is a statement about case metadata and synthetic bodies, not about
the target. --check regenerates the document in memory and fails if the stored file differs, so the file cannot be
hand-edited. campaign-latest.json is never read for writing and is never touched.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agentforge.evals.cases import load_cases  # noqa: E402
from agentforge.evals.offline import RESULT_PATH, build_document, load_pairs, render_document  # noqa: E402
from agentforge.safety.phi import PhiRefused  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the stored file differs from a fresh run")
    args = parser.parse_args(argv)
    cases = load_cases()
    document = build_document(cases, load_pairs())
    try:
        text = render_document(document)
    except PhiRefused as exc:
        print(f"FAIL offline result matches a PHI pattern: {', '.join(exc.kinds)}")
        return 1
    if args.check:
        if not RESULT_PATH.is_file():
            print("FAIL offline-latest.json is missing")
            return 1
        if RESULT_PATH.read_text(encoding="utf-8") != text:
            print("FAIL offline-latest.json differs from a fresh run; do not edit it by hand")
            return 1
        print(f"OK offline-latest.json matches a fresh run, {len(document['results'])} cases, live false")
        return 0
    RESULT_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULT_PATH.write_text(text, encoding="utf-8")
    print(f"wrote {RESULT_PATH.relative_to(ROOT)}, {len(document['results'])} cases, live false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
