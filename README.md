# AgentForge Platform

Adversarial AI security platform for the AgentForge Clinical Co-Pilot (Gauntlet AI, Week 3).

**Status: P5 (architecture and MVP pack), on top of P0 to P4.** The committed code makes no request to the target
and calls no model. `LIVE_ENABLED` and `PROVIDER_ENABLED` are both `False` in committed code, and an environment
variable cannot turn either on. Anything not listed under "Built" is **(planned)** and must not be described as
working.

Start with [ARCHITECTURE.md](ARCHITECTURE.md). It names the four agents, marks each claim Built or Planned, and
links the schemas, threat model and decisions.

## What this repo is

An independent repository (repo strategy B, see [ADR-001](Docs/adr/001-repo-strategy.md)). The Co-Pilot is an
external HTTP target and is not part of this repository. The platform pins the target by commit SHA and reaches it
only over HTTP. See [TARGET_FREEZE.md](Docs/TARGET_FREEZE.md).

## Built

- **Safety envelope** (`src/agentforge/safety/`, `config/`): a default-deny allowlist, one HTTP chokepoint, a budget
  with an attack cap and kill switch, an operator approval gate, a request-rate cap, a refusal log (created at runtime
  at `evals/results/refusals.log` by the live scripts, so a fresh clone does not have it), a PHI scan, and a
  persistent shared ledger with a $5 ceiling (`ledger.py`).
- **Contracts and store** (`contracts/v1/`, `src/agentforge/contracts/`, `src/agentforge/store/`): versioned
  message and error schemas, and a SQLite store that rejects a duplicate sequence, a missing field and a published
  status.
- **Seed suite and executor** (`evals/cases/`, `src/agentforge/evals/`): seven synthetic cases across TM-PI, TM-EX
  and TM-DS, deterministic graders, and a session client for the target login and chat.
- **Judge** (`src/agentforge/agents/judge.py`): deterministic rules first, a model only for an ambiguous transcript.
  A labeled set and a drift procedure are in `evals/judge/` and [JUDGE_DRIFT.md](Docs/JUDGE_DRIFT.md).
- **Red Team, partial** (`src/agentforge/agents/red_team.py`): `SeedMutator`, a deterministic mutator. It calls no
  model.
- **Model config** (`config/models.yaml`, `src/agentforge/models_config.py`): Red Team and Judge must use different
  model families. The probe record is [MODEL_PROBE.md](Docs/MODEL_PROBE.md).
- **CI** (`.github/workflows/ci.yml`): lint, mypy, tests with a coverage floor, Bandit, secret scan, link check,
  workflow guard, schema and suite checks. CI makes no live or paid calls.

## Evidence so far

- A local, operator-run campaign graded three cases `pass` against the target at `127.0.0.1:8300`: TM-PI-1,
  TM-EX-3 and TM-DS-1 (`evals/results/campaign-latest.json`). One live `SeedMutator` turn is in
  `evals/results/agent-live.json`. These are defense-held results, not discovered exploits.
- The Judge was measured on four labeled items and one provider-scored ambiguous item. That is not a rate.
- Spend to date is $0.1022 of the $5.00 shared ceiling. See the spend log in [PROGRESS.md](Docs/PROGRESS.md).
- GitHub Actions passed on commit `22e7983` (reported by the operator). Changes made after that commit are not
  CI-verified until they are pushed.

## Deployed link

**None. Open gap G-1 (hard gate H-1). Owner: the operator.** No public URL exists, and the target has only been
tested at `127.0.0.1:8300`. Closeout steps are in the deployment note in [ARCHITECTURE.md](ARCHITECTURE.md). The
Cloudflare quick tunnel question is Q2 in [DECISIONS.md](Docs/DECISIONS.md).

## Planned (not built)

- **P6:** Orchestrator, model-driven Red Team, persisted run state.
- **P7:** regression harness and Documentation agent.
- **P8:** observability queries and load tests.
- **P9:** the platform's own access control and security review.
- Later checkpoints are in [ROADMAP.md](Docs/ROADMAP.md). Progress and evidence: [PROGRESS.md](Docs/PROGRESS.md).
  Decisions and open questions: [DECISIONS.md](Docs/DECISIONS.md).

## Setup

Python 3.12 is required (`pyproject.toml`).

```
python3.12 -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
pip install -e .
pytest
```

## Dry run (no network, no model, no spend)

```
python scripts/check_evals.py
```

This validates every case against `evals/schema/case.schema.json`, scans fixtures for PHI patterns, and runs the
suite in dry-run mode. It exits 0 and prints `OK 7 cases ... dry-run fabricated no pass`. A dry run never reports a
`pass`: a case that needs a target is `not_run`. Replay of a recorded transcript is covered by `tests/test_evals.py`.

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
python scripts/check_architecture.py
python scripts/check_schema_diff.py
python scripts/check_evals.py
```

## Live execution (operator-gated)

The committed code cannot run live. Only the operator can enable it, and only on their own machine. This section
describes the gates and does not do any of it for you.

1. Review and make a local edit to `config/allowlist.yaml` so it admits the target host. A change here is reviewed
   like code.
2. Copy `.env.example` to `.env` (git-ignored) and fill in the operator-held values: the budget secret and token, the
   target origin, the fixture credentials, and the per-chat reserve. Never paste a key or password into chat or a
   tracked file.
3. Copy `config/operator_approval.example.yaml` to `config/operator_approval.yaml` (git-ignored) and record a $5
   approval. This is an operator approval, not a provider-dashboard attestation, and it does not prove a provider
   limit exists.
4. Set `LIVE_ENABLED` in `src/agentforge/safety/chokepoint.py` to `True` locally for a target run. Set
   `PROVIDER_ENABLED` locally for a model call. Revert both before committing. Neither can be set from the
   environment.
5. Run one script: `scripts/live_identity.py` (login-page check), `scripts/live_campaign.py` (graded cases),
   `scripts/live_agent.py` (one `SeedMutator` turn), `scripts/probe_models.py` or `scripts/live_judge.py` (provider
   calls). Each reserves in the shared ledger before it sends and refuses past the $5 ceiling.

Provider-side spend limits (E-6) are still not attested: `config/spend_limits.yaml` has no entry, and an operator
approval stands in for it during local testing. The shared OpenRouter key had exceeded its own provider limit
earlier on 2026-10-19 and the first probe was refused with a 403. The key owner then raised the limit, and the
later probe and Judge calls completed (see [MODEL_PROBE.md](Docs/MODEL_PROBE.md)). Raising the limit is not an
attestation, so E-6 stays open and belongs to the key owner.

## Safety rules

- Live requests are refused until the target is on `config/allowlist.yaml` through a reviewed change, a budget is
  approved, and an operator approval or a provider-side spend limit attestation is present.
- Never commit keys, passwords, tokens, `.env` files or real patient data. Fixtures are synthetic only.
