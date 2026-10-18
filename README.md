# AgentForge Platform

Adversarial AI security platform for the AgentForge Clinical Co-Pilot (Gauntlet AI, Week 3).

**Status: P3 in progress (seed suite and deterministic executor). Nothing has attacked the target.** This
repository makes no request to the target, calls no model and spends no money. `LIVE_ENABLED` is false. An
environment variable cannot turn it on. Everything not listed under "Runnable today" is **(planned)** and must
not be described as working.

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

## Written in P1 (documents, not code that runs)

- [THREAT_MODEL.md](THREAT_MODEL.md): the six attack categories, the OWASP mapping, and the platform's own threats.
  Every defense it cites was established by reading the target's code, not by running it.
- [USERS.md](USERS.md): who the platform is for and why automation is the right tool. Its checkpoint is unconfirmed.
- [Docs/PRD_TRACEABILITY.md](Docs/PRD_TRACEABILITY.md): every PRD requirement, the checkpoint that owns it, and the
  evidence so far.

## Runnable today (P2)

- Versioned message schemas in `contracts/v1/`, validated by the pinned `jsonschema` library
  (`src/agentforge/contracts/`). Agent protocols in `src/agentforge/agents/` name those messages and do nothing else.
  No agent is implemented.
- A SQLite schema for exploits, regression cases, run logs and coverage metrics (`src/agentforge/store/`). Inserts
  reject a duplicate attack sequence, a missing required field and a published status. Who may write is a design
  record, [ACCESS_CONTROL.md](Docs/ACCESS_CONTROL.md), not an enforced role.

## Runnable today (P3)

- A seed suite of six synthetic cases in `evals/cases/` across TM-PI, TM-EX and TM-DS. Dry-run is the default and
  does not open a socket. A case that needs a target is `not_run`, not `pass`.
- Deterministic graders for a canary, a patient-id boundary, a missing session and the attack-count cap
  (`src/agentforge/evals/`). Replay grades a recorded transcript. It does not call the target.
- Refusal log, login-page identity check, request-rate cap and a PHI scan before a result is written
  (`src/agentforge/safety/`). The allowlist file is still empty, so a live call is refused.
- No graded result against the deployed target exists. That run is manual and has not been started.

## Planned (not built)

Judge, Red Team, Orchestrator, Documentation agent, regression harness, observability, load tests. One agent role
live against the target is P4, not this checkpoint.
Plan: [ROADMAP.md](Docs/ROADMAP.md). Progress and evidence: [PROGRESS.md](Docs/PROGRESS.md).
Decisions and open questions: [DECISIONS.md](Docs/DECISIONS.md).

## Target

- Pinned commit and caveats: [TARGET_FREEZE.md](Docs/TARGET_FREEZE.md).
- Deployed URL: provisional and unconfirmed. The Cloudflare quick tunnel URL rotates (Q2). Reachability is
  UNVERIFIED. P3 did not request the login page.

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
python scripts/check_threat_model.py
python scripts/check_schema_diff.py
python scripts/check_evals.py
```

## Safety rules

- Live requests are refused until the target is on `config/allowlist.yaml` through a reviewed change, a budget is
  approved, and a provider-side spend limit is attested (`config/spend_limits.yaml`).
- Never commit keys, passwords, tokens, `.env` files or real patient data. Fixtures are synthetic only.
