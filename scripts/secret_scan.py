#!/usr/bin/env python3
"""Secret scan over tracked and not-ignored files plus git history. Exit 1 on any hit.

Adapted from the target repo's scripts/copilot/secret_scan.py (copied, not imported). The agent .env and OpenEMR
skip lists are removed. Looks for private keys and OpenRouter, OpenAI, Anthropic, GitHub and AWS style tokens, and for
the literal values of secrets in a git-ignored .env at the repo root. Usage: secret_scan.py [repo_root]
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

PATTERNS = {
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "openrouter key": re.compile(r"sk-or-v1-[A-Za-z0-9]{20,}"),
    "anthropic key": re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"),
    "openai-style key": re.compile(r"\bsk-[A-Za-z0-9]{32,}\b"),
    "github token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "aws access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
}
SKIP_SUFFIXES = (".png", ".jpg", ".gif", ".pdf", ".zip", ".woff", ".woff2", ".ico", ".lock", ".map")


def env_secrets(root: Path) -> list[str]:
    env = root / ".env"
    out: list[str] = []
    if env.exists():
        for line in env.read_text(errors="ignore").splitlines():
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                if any(w in k.upper() for w in ("KEY", "SECRET", "TOKEN", "PASSWORD")) and len(v.strip()) >= 12:
                    out.append(v.strip())
    return out


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=root, capture_output=True, text=True, check=True, errors="replace"
    ).stdout


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) > 1 else Path(__file__).resolve().parents[1]
    secrets = env_secrets(root)
    hits: list[str] = []

    def scan(label: str, text: str) -> None:
        for name, rx in PATTERNS.items():
            if rx.search(text):
                hits.append(f"{label}: {name}")
        for s in secrets:
            if s in text:
                hits.append(f"{label}: value of a secret from .env")

    # Working tree: tracked files plus untracked files that are not git-ignored, so a key is caught before commit.
    for path in git(root, "ls-files", "--cached", "--others", "--exclude-standard").splitlines():
        if path.endswith(SKIP_SUFFIXES):
            continue
        try:
            scan(path, (root / path).read_text(errors="ignore"))
        except OSError:
            continue

    # History: added lines only. An empty repository has no history yet.
    try:
        patch = git(root, "log", "--all", "-p", "--no-color", "--pretty=format:commit %h")
    except subprocess.CalledProcessError:
        patch = ""
    commit = "?"
    for line in patch.splitlines():
        if line.startswith("commit "):
            commit = line.split()[1]
        elif line.startswith("+") and not line.startswith("+++"):
            scan(f"history {commit}", line)

    for h in sorted(set(hits)):
        print("HIT", h)
    print(f"secret scan: {len(set(hits))} hit(s)")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
