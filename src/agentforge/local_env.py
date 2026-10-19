"""Load a gitignored local .env. Existing process variables win.

This follows the Project 2 settings rule: secrets come from the environment or a
git-ignored .env, and a name already set in the process is not replaced. Unknown
lines are ignored. Live-switch names are ignored so a local file cannot enable a call.
Values are never printed.
"""

from __future__ import annotations

import os
from pathlib import Path

_SWITCHES = frozenset(
    {
        "LIVE_ENABLED",
        "PROVIDER_ENABLED",
        "AGENTFORGE_LIVE",
        "AGENTFORGE_LIVE_ENABLED",
        "AGENTFORGE_PROVIDER_ENABLED",
    }
)


def load_local_env(path: Path) -> None:
    """Apply KEY=value lines. A missing file leaves the environment unchanged."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        name = name.strip()
        if name.startswith("export "):
            name = name[7:].strip()
        if not name or name in _SWITCHES or not name.replace("_", "").isalnum():
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        os.environ.setdefault(name, value)
