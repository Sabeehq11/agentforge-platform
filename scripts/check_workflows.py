#!/usr/bin/env python3
"""Workflow guard. Exit 1 if any workflow could expose secrets to untrusted code or lacks least privilege.

Rules: no pull_request_target trigger; every workflow declares top-level permissions; no write permissions;
no workflow in this repo may reference secrets. A schedule is allowed only with contents: read, no secrets,
no live path, and no reference to the local store. Usage: check_workflows.py [repo_root]
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

import yaml


def has_write(perms: Any) -> bool:
    if isinstance(perms, dict):
        return any(str(v).lower() == "write" for v in perms.values())
    return isinstance(perms, str) and "write" in perms.lower()


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) > 1 else Path(__file__).resolve().parents[1]
    files = sorted((root / ".github" / "workflows").glob("*.y*ml"))
    problems: list[str] = []
    if not files:
        problems.append("no workflow files found")
    for f in files:
        text = f.read_text()
        name = f.name
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            problems.append(f"{name}: invalid YAML ({exc})")
            continue
        if not isinstance(data, dict):
            problems.append(f"{name}: not a mapping")
            continue
        # PyYAML parses the bare key `on` as boolean True.
        triggers = data.get("on", data.get(True))
        trig = set(triggers) if isinstance(triggers, (dict, list)) else {triggers}
        # Parsed trigger keys, plus a YAML-key or list-item match that ignores comments and step names.
        key_form = re.search(r"^\s*(?:-\s*)?pull_request_target\s*:?\s*(?:#.*)?$", text, re.M)
        if "pull_request_target" in trig or key_form:
            problems.append(f"{name}: pull_request_target is forbidden")
        perms = data.get("permissions")
        if perms is None:
            problems.append(f"{name}: missing top-level permissions")
        elif has_write(perms):
            problems.append(f"{name}: write permission is not allowed")
        for job_name, job in (data.get("jobs") or {}).items():
            if isinstance(job, dict) and has_write(job.get("permissions")):
                problems.append(f"{name}: job {job_name} requests write permission")
        if re.search(r"\$\{\{\s*secrets\.", text):
            problems.append(f"{name}: secrets are not available to workflows in this repo")
        scheduled = "schedule" in trig or "workflow_dispatch" in trig
        if scheduled:
            if perms != {"contents": "read"}:
                problems.append(f"{name}: a schedule must declare contents: read and nothing else")
            if "LIVE_ENABLED" in text or "agentforge.db" in text:
                problems.append(f"{name}: a schedule must not set LIVE_ENABLED or open the local store")
            if "pull_request" in trig:
                problems.append(f"{name}: a schedule must not also run on pull_request")
    for p in problems:
        print("WORKFLOW", p)
    print(f"workflow check: {len(files)} file(s), {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
