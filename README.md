# AgentForge Platform

Adversarial AI security platform for the AgentForge Clinical Co-Pilot (Gauntlet AI, Week 3).

**Status: P11 documentation pass, on commit `17827fb`.** P0 to P10 are committed. Scripted and stub paths for the
four agents are built. A live run of the four agents together is not. The committed code makes no request to the
target and calls no model. `LIVE_ENABLED` and `PROVIDER_ENABLED` are both `False` in committed code, and an
environment variable cannot turn either on. Anything not listed under "Built" is **(planned)** or unmet, and must
not be described as working.

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
- **Seed suite and executor** (`evals/cases/`, `src/agentforge/evals/`): thirteen synthetic cases across TM-PI, TM-EX,
  TM-DS, TM-ID and TM-TM, deterministic graders, and a session client for the target login and chat. Every case
  passes the PRD p.11 validity gate on case metadata and synthetic bodies, which is not a finding about the target.
  `evals/owasp_coverage.json` is a coverage ledger that closes no PRD requirement: A04 is an unverified Co-Pilot rate-limit case and
  A09 is a platform-trace case, and neither is a closed row, A01 is offline only (cases and synthetic replays, no
  target outcome), LLM02, LLM06 and LLM08 are partially exercised, and the LLM08 case is a response-claim proxy,
  not tool-invocation proof. `evals/results/offline-latest.json` holds synthetic safe and weakened replays. They are not
  target results. The unobserved halves are named in [PRD_TRACEABILITY.md](Docs/PRD_TRACEABILITY.md) as R10 and the
  open gaps U1 to U5. None of those has run.
- **Judge** (`src/agentforge/agents/judge.py`): deterministic rules first, a model only for an ambiguous transcript.
  A labeled set and a drift procedure are in `evals/judge/` and [JUDGE_DRIFT.md](Docs/JUDGE_DRIFT.md).
- **Orchestrator, scripted** (`src/agentforge/orchestrator/`, `scripts/orchestrate.py`): a crash-safe dispatch journal,
  ranking, bounded retries and a cost stop. `python scripts/orchestrate.py --dry-run` runs one scripted campaign.
  That is not a live campaign. A P7 stub run can extend that trace through the Documentation agent under the same
  correlation ID. `python scripts/regress.py` replays a pending handoff on an in-process stub and refuses `--live`.
- **Red Team** (`src/agentforge/agents/red_team_generator.py`): strict model-output validation and a novelty check.
  Tests use a scripted model. `SeedMutator` remains for the P4 path and calls no model.
- **Model config** (`config/models.yaml`, `src/agentforge/models_config.py`): Red Team and Judge must use different
  model families. The probe record is [MODEL_PROBE.md](Docs/MODEL_PROBE.md).
- **Observability and load** (`src/agentforge/observe/`, `scripts/observe.py`, `scripts/loadtest.py`): the six PRD
  questions, an offline baseline, a stub regression SLO, and a measured D-13 run of 100 of 100 chats on the Week 1
  stub route (`evals/results/d13-load.json`). Orchestration took 90.13541795802303 seconds. Stub LLM latency was
  0.0 seconds. Storage wrote 5991.5354876013225 rows per second. The bottleneck is the agent's 60-chat rolling
  minute. Measured stub spend is `$0`. That is not a real-provider benchmark. See [LOAD_TEST.md](Docs/LOAD_TEST.md).
- **Platform security, in-process** (`src/agentforge/store/access.py`, `scripts/self_scan.py`): role-scoped grants,
  content rules, and a self-scan of pytest, mypy, Bandit and pip-audit. `approved_by` is a label, not an
  authenticated principal.
- **P10 evidence, offline** (`evals/triage/scan-report.json`, `Docs/ATO_PACKET.md`, `Docs/COST_ANALYSIS.md`,
  `evals/results/drills-p10.json`): triage, an ATO packet, failure drills and a cost analysis. The integration
  packet is a stub conformance test, not peer integration (`Docs/INTEGRATION_PACKET.md`).
- **CI** (`.github/workflows/ci.yml`): lint, mypy, tests with a coverage floor, Bandit, secret scan, link check,
  workflow guard, schema and suite checks, and a P10 evidence-file presence check. CI makes no live or paid calls.

## Evidence so far

- A local, operator-run campaign graded three cases `pass` against the target at `127.0.0.1:8300`: TM-PI-1,
  TM-EX-3 and TM-DS-1 (`evals/results/campaign-latest.json`). One live `SeedMutator` turn is in
  `evals/results/agent-live.json`. These are defense-held results, not discovered exploits.
- One public campaign, `corr-live-fix-20261023`, finished `done` against the deployed target on pin `9f03654`
  (`evals/results/public-campaign-20261023.json`). Two chat attacks were judged `pass`. The journal records the executor. No exploit was confirmed,
  and the target reply text is not in the file. That is not a vulnerability report.
- The Judge was measured on four labeled items and one provider-scored ambiguous item. That is not a rate.
- D-13: 100 of 100 completed on the Week 1 stub route, `live: true`, `zero_cost_stub: true`, measured spend `$0`.
  Not a provider-model run. Details are in [LOAD_TEST.md](Docs/LOAD_TEST.md).
- Spend to date is $0.1522 of the $5.00 shared ceiling (16 ledger rows; $0.1500 of it is three target reservations written as incurred). See the spend log in [PROGRESS.md](Docs/PROGRESS.md).
  The `$0.05` projection unit is a reservation, not the D-13 measurement.
- GitHub Actions passed on commit `22e7983` (reported by the operator). Later commits, including `17827fb`, are
  not CI-verified in this repo until a run log exists. This pass does not push.

## Deployed link

The public campaign `corr-live-fix-20261023` ran against
`https://char-boot-podcasts-competition.trycloudflare.com` on pin `9f03654`. The graded result, without target
reply text, is [evals/results/public-campaign-20261023.json](evals/results/public-campaign-20261023.json). Both
verdicts were `pass`. That file is not a vulnerability report, and it is not proof the tunnel is still up. The
hostname is not in the tracked allowlist. Copy `config/allowlist.local.example.yaml` to the gitignored
`config/allowlist.local.yaml` and set `public_host` to the hostname from the current tunnel. A missing file adds
no public host. The isolated stack on port 19300 is not the campaign target.

## Not verified live

Scripted and stub paths above are built. These are not:

- A live Orchestrator campaign, and a live run of all four agents under one correlation ID.
- A live regression replay against a public target. Reports in `reports/` are fixture drafts, not deployed findings.
  A report's source line is `fixture`, `unverified` or `recorded_verified`, and a fix-validation line states its
  replay basis: `stub` (a canned reply, not the target), `client_verified` (transport and sequence provenance only,
  not a validated fix) or `unverified`. The labels do not gate `fixed`. `recorded_verified` and `client_verified` have
  been proven only on constructed facts, and no report carries either today.
- A real-provider load benchmark. D-13 measured the Week 1 stub route at `$0`.
- A public deployed URL (H-1). Owner: the operator. Q2 is open.
- Peer integration. No cohort peer was assigned. The stub packet is not that integration.
- A provider-side spend-limit attestation (E-6). Owner: the key owner.

Progress and evidence: [PROGRESS.md](Docs/PROGRESS.md). The requirement ledger is
[PRD_TRACEABILITY.md](Docs/PRD_TRACEABILITY.md). Decisions: [DECISIONS.md](Docs/DECISIONS.md).

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
python scripts/run_offline_cases.py --check
python scripts/regress.py
python scripts/check_reports.py
python scripts/observe.py
python scripts/check_p10_evidence.py
```

This validates every case against `evals/schema/case.schema.json`, scans fixtures for PHI patterns, and runs the
suite in dry-run mode. It also checks the OWASP ledger and the p.11 gate for every case. It exits 0 and prints `OK 19 cases ... dry-run fabricated no pass`. A dry run never reports a
`pass`: a case that needs a target is `not_run`. Replay of a recorded transcript is covered by `tests/test_evals.py`.
`scripts/regress.py` refuses `--live` and does not open a socket. `scripts/check_reports.py` checks the three draft
reports. `scripts/observe.py` prints the six observability answers from the local store and has no live path.
`scripts/check_p10_evidence.py` checks that the P10 files exist and are labeled. It does not fetch or scan.

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

1. Copy `config/allowlist.local.example.yaml` to `config/allowlist.local.yaml` (gitignored) and set `public_host`
   to the exact hostname from the current Cloudflare quick tunnel for `https://127.0.0.1:9300`. No wildcard, no
   port 19300, and no edit to the tracked allowlist.
2. Copy `.env.example` to `.env` (git-ignored) and fill in the operator-held values: the budget secret and token, the
   target origin, the fixture credentials, and the per-chat reserve. Never paste a key or password into chat or a
   tracked file.
3. Copy `config/operator_approval.example.yaml` to `config/operator_approval.yaml` (git-ignored) and record a $5
   approval. This is an operator approval, not a provider-dashboard attestation, and it does not prove a provider
   limit exists.
4. Write the single word `live` into gitignored `config/live.local`. That is the only runtime opt-in, and it sets
   both switches for that process. A missing file, or any other text, leaves both false. Do not edit the source
   constants. `AGENTFORGE_LIVE_OPT_IN=live` in the process is the same token; any other value stays off.
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
