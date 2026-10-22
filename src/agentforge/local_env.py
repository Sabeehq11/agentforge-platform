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
# The one name a gitignored .env may set. It is applied only by apply_runtime_opt_in, and only if the value is
# the exact token. A process variable of the same name still wins, so a shell cannot be overridden by the file.
_OPT_IN = "AGENTFORGE_LIVE_OPT_IN"


def load_local_env(path: Path, *, override: frozenset[str] = frozenset()) -> None:
    """Apply KEY=value lines. A missing file leaves the environment unchanged.

    is_file() first, so a missing file does not open. Callers that forbid opening .env rely on that.
    A name in override is taken from the file when the file sets it, so a stale process value cannot
    redirect that setting. Every other existing process variable still wins.
    """
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
        if name == _OPT_IN and value.strip() != "live":
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        if name in override:
            os.environ[name] = value
        else:
            os.environ.setdefault(name, value)
