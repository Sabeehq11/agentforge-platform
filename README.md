# AgentForge Platform

Adversarial AI security platform for the AgentForge Clinical Co-Pilot (Gauntlet AI, Week 3).

**Status: P0 (foundations). Nothing attacks anything yet.** This repository makes no request to the target, calls
no model and spends no money. Everything not listed under "Runnable today" is **(planned)** and must not be
described as working.

## What this repo is

An independent repository (repo strategy B, see [ADR-001](Docs/adr/001-repo-strategy.md)). The Co-Pilot is an
external HTTP target and is not part of this repository. The platform pins the target by commit SHA and reaches it
only over HTTP. See [TARGET_FREEZE.md](Docs/TARGET_FREEZE.md).

## Runnable today (P0)

- A default-deny target allowlist, a cost budget with an approval token and kill switch, a provider spend-limit
  attestation gate, and one HTTP chokepoint that runs them in order. `LIVE_ENABLED` is `False`, so no real
  transport exists. Code: `src/agentforge/safety/`. Config: `config/`.
- A check that Red Team and Judge models come from different families (`src/agentforge/models_config.py`).
- Tests for all of the above (`tests/`), including a test that no socket is opened.
- CI (`.github/workflows/ci.yml`): lint, mypy, tests with a coverage floor, Bandit, secret scan, markdown link
  check and a workflow guard. CI makes no live or paid calls.

## Planned (not built)

Threat model, contracts, attack suite, Judge, Red Team, Orchestrator, Documentation agent, regression harness,
observability, load tests. Plan: [ROADMAP.md](Docs/ROADMAP.md). Progress and evidence: [PROGRESS.md](Docs/PROGRESS.md).
Decisions and open questions: [DECISIONS.md](Docs/DECISIONS.md).

## Target

- Pinned commit and caveats: [TARGET_FREEZE.md](Docs/TARGET_FREEZE.md).
- Deployed URL: provisional and unconfirmed. The Cloudflare quick tunnel URL rotates (Q2). Reachability is
  UNVERIFIED in P0.

## Develop

Python 3.12 is required (`pyproject.toml`).

```
python3.12 -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
pip install -e .
pytest
```

Local checks that CI also runs:

```
ruff check src tests scripts --select E9,F63,F7,F82
mypy src
pytest --cov=agentforge --cov-fail-under=85
bandit -r src -ll -iii -q
python scripts/secret_scan.py
python scripts/check_links.py
python scripts/check_workflows.py
python scripts/check_adrs.py
```

## Safety rules

- Live requests are refused until the target is on `config/allowlist.yaml` through a reviewed change, a budget is
  approved, and a provider-side spend limit is attested (`config/spend_limits.yaml`).
- Never commit keys, passwords, tokens, `.env` files or real patient data. Fixtures are synthetic only.
