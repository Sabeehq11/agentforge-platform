# Week 3 progress

Tracks checkpoints P0 to P11. The plan is in [ROADMAP.md](ROADMAP.md). Decisions and open questions are in
[DECISIONS.md](DECISIONS.md). The Week 3 PRD is authoritative.

Update rule: a checkpoint is `done` only when every verification line under it has evidence recorded here (a command,
a file path or a result). Built without evidence is `in progress`. Nothing is marked done from memory.

Status values: `not started`, `in progress`, `blocked`, `done`.

## Milestones

| Milestone | Due (PRD) | Checkpoints | Status |
|---|---|---|---|
| Architecture Defense | 4 hours after kickoff | P0, drafts of P1 and P2 | P0 done (reachability deferred to P3), P1 not started |
| MVP | Tuesday 11:59 PM | P0 to P5 | not started |
| Final | Friday noon | P6 to P11 | not started |

The kickoff time is not recorded in the repo, so the Architecture Defense deadline is unconfirmed.

## Safety envelope (all must be done before the first live attack)

| Control | Status | Evidence |
|---|---|---|
| Target allowlist, default deny, one HTTP chokepoint | in progress | Skeleton and tests in P0. No live transport, no hosts listed |
| Target identity check | not started | |
| Synthetic-data fixtures and transcript scan | not started | |
| Per-run and per-day USD caps, attack-count cap, approval token | in progress | `budget.py` and tests in P0. Not approved for any run |
| Provider-side spending limit on every key (DECISIONS Q13) | in progress | Attestation gate in P0 refuses while `spend_limits.yaml` is empty. Limits not set |
| Per-agent cost metering and kill switch | in progress | Kill switch in `budget.py`. Per-agent metering is P4 |
| Request-rate cap toward the target | not started | |
| Human approval for over-cap runs, new allowlist entries, load tests | not started | |

## Deliverables (PRD submission table)

| Deliverable | Needed at | Status | Notes |
|---|---|---|---|
| Deployed target URL | every checkpoint | not started | Quick tunnel URL rotates (Q2) |
| GitHub repo with setup guide and run instructions | MVP | in progress | Layout decided: independent repo (ADR-001). README is P0-level |
| `THREAT_MODEL.md` | MVP | not started | P1 |
| `USERS.md` | MVP **(unconfirmed)** | not started | P1 |
| `ARCHITECTURE.md` | MVP | not started | P5 |
| `/contracts` | MVP first version | not started | P2 |
| `evals/` with 3+ categories of results | MVP | not started | P3 |
| One agent live against the target | MVP | not started | P4 |
| Vulnerability reports (3 minimum) | Final, MVP unconfirmed (Q5) | not started | P7 |
| AI cost analysis | Final, actual spend at MVP | not started | P10 |
| Demo video, 3 to 5 minutes | MVP unconfirmed (Q5), Final | not started | P11 |
| Social post | Final | not started | P11 |
| Build-versus-configure record | Architecture Defense | in progress | P0. `Docs/BUILD_VS_CONFIGURE.md`, tool claims unverified |
| Defense evidence packet | Architecture Defense | in progress | P0. `Docs/DEFENSE_PACKET.md` draft |
| Triage lab | Final | not started | P10 |
| ATO-style evidence packet | Final | not started | P10 |
| Integration packet | Final, peer dependent (Q4) | not started | P10 |

## Checkpoints

### P0. Foundations and decisions
- Status: **done**, with one recorded exception. Depends on: nothing.
  - Commit: `4bbd1b6` (`feat: establish AgentForge P0 foundation`, full SHA
    `4bbd1b6d400a533e22891a2aa0a71b3b4bac4ab6`), pushed to `origin/main` on 2026-10-17. `git ls-remote origin main`
    returned that SHA. It is the first commit in the repo and was not force pushed.
  - GitHub Actions CI #1: **passed**, as reported by the user. The assistant did not confirm this: `gh` is not installed
    here and the private repo returns 404 to unauthenticated API calls, so there is no run log in this repo.
  - Tests: 74 automated tests (96.26% coverage on Python 3.12.15) and four manual smoke tests, all passing. The smoke
    tests are user-reported, see the evidence below.
  - Exception to the update rule: target reachability has no evidence. By decision it is deferred to P3 and is not a
    P0 gate. P0 makes zero target requests. The reachability line below stays unchecked.
  - Not cleared by P0: provider spend-limit attestation (Q13) is pending and must be done before any live testing.
- [x] Repo-strategy ADR: `Docs/adr/001-repo-strategy.md`
- [x] Build-versus-configure record: `Docs/BUILD_VS_CONFIGURE.md` (tool claims marked unverified)
- [x] ADRs: framework (003), models (004), state store (005), observability (006), plus 002 target access and 007 URL
- [x] Target freeze: `Docs/TARGET_FREEZE.md` (SHA `9f03654`, fork main `efb66b5`, same tree; URL provisional)
- [x] Safety-envelope skeleton: `src/agentforge/safety/` and `config/` (no network code, `LIVE_ENABLED = False`)
- [x] Draft Defense evidence packet: `Docs/DEFENSE_PACKET.md`
- [x] Verify: ADRs name rejected alternatives (`scripts/check_adrs.py`: 7 ADRs, 0 problems; a one-alternative ADR failed)
- [ ] Verify: target reachability. **UNVERIFIED, deferred to P3** (exception to the update rule, see Status). P0 makes
  zero target requests. The agent's `/ready` is private by design, so the later check is a read-only GET of the public
  OpenEMR login page.
- [x] Verify: allowlist default-deny unit test (`tests/test_allowlist.py`, `tests/test_chokepoint.py`)
- [x] CI written: `.github/workflows/ci.yml` (lint, mypy, tests and coverage, Bandit, secret scan, link check, ADR
  check, workflow guard). GitHub Actions CI #1 on commit `4bbd1b6`: **passed, user-reported**. Not independently
  confirmed by the assistant, and no run log is stored here.
- Evidence, rerun 2026-10-17 on Python **3.12.15** (Homebrew `python@3.12`, venv under `/tmp`, tools at the pinned
  versions). The same commands passed earlier on 3.10.13, with identical results:
  - `ruff check src tests scripts --select E9,F63,F7,F82`: All checks passed.
  - `mypy src` (strict): no issues in 7 source files.
  - `pytest --cov=agentforge --cov-fail-under=85`: 74 passed, coverage 96.26%, on 3.12.15. Every test runs with sockets patched
    to fail (`tests/conftest.py`), and the chokepoint tests assert the transport is never called when a gate fails.
  - `bandit -r src -ll -iii -q`: no findings.
  - `scripts/secret_scan.py`: 0 hits on the repo. A planted `sk-or-v1-` style key exits 1. A value copied from a
    git-ignored `.env` into a file exits 1. Both plants were removed.
  - `scripts/check_links.py`: 25 internal links, 0 problems. A wrong-case path and a missing anchor both exit 1.
  - `scripts/check_workflows.py`: 0 problems. A `pull_request_target` trigger, missing permissions and a `secrets.`
    reference each exit 1 (temp directory).
  - Weakening the allowlist in a temp copy (empty allowlist allows) makes pytest fail (rc 1). Removing the chokepoint's
    allowlist gate in a temp copy also fails pytest (rc 1). The working tree was not changed.
  - The whole suite also passes with `socket.socket`, `create_connection` and `getaddrinfo` replaced by a function that
    exits, set before pytest starts (no reliance on the conftest fixture).
  - Diff review (nothing is committed, so this is the untracked file set, 47 files): no key, token, password or
    private-key pattern in any text file. Only dummy test strings and a documentation example hostname. The three PDFs in
    `Docs/` were text-extracted and scanned: no credential pattern. `Project3_Engineering_Handoff.pdf` contains one
    `trycloudflare.com` hostname, which the handoff says is ephemeral and stale. It is a hostname, not a secret.
  - Planning doc sha256 before P0 edits are in `TARGET_FREEZE.md`. ROADMAP and DECISIONS were then edited on purpose
    (path labels, reachability line, D-010 to D-012). PROGRESS.md was unchanged until this entry.
  - At the time of that review nothing was committed. The commit came afterwards (`4bbd1b6`, see Status). No file
    outside this repo was written except the throwaway venv in `/tmp`. No request was made to the target, no model was called, no money spent.
- Manual smoke tests, executed by the user on 2026-10-17 against local-only test data, with sockets blocked and no
  repo files modified. All four were reported successful. The assistant did not run them and did not see their output,
  so this is user-reported evidence, and the exact terminal output was not captured here.
  - Allowlist: the shipped empty `config/allowlist.yaml` denies everything. A temp allowlist allowed only the exact
    matching URL and denied wrong scheme, host, port, path, traversal, userinfo and off-list redirect.
  - Budget enforcement: reserve before approval, a wrong token, a token for different caps and an empty secret were all
    rejected, and the per-run and attack-count caps raised before overspend.
  - Kill switch: once engaged, the next reserve raised `KillSwitchEngaged`.
  - Missing spend-limit attestation: the shipped `config/spend_limits.yaml` (no attestations) refuses OpenRouter use, so
    the chokepoint refuses at the `spend_limit` gate. No attestation was created and no provider was queried.
- Not verified, and why:
  - Python 3.12 is no longer an open item: all checks passed on 3.12.15 locally, and CI #1 on GitHub's runner passed
    per the user.
  - GitHub Actions: the push worked (`4bbd1b6` is on `origin/main`). The CI #1 pass is user-reported and not independently
    confirmed by the assistant.
  - Target reachability, synthetic identity existence and whether the running stack equals the pinned SHA (A-001, A-004).
  - Provider-side spend limits (Q13): the gate exists and refuses; the limits are not set or attested.

### P1. Threat model and users
- Status: not started. Depends on: P0.
- [ ] `THREAT_MODEL.md` with ~500-word summary
- [ ] Six PRD categories with surface, impact, difficulty, existing defenses
- [ ] OWASP Top 10 and LLM Top 10 mapping, non-applicable items explained
- [ ] Platform-side threats
- [ ] `USERS.md`
- [ ] Verify: defenses cited to files
- [ ] CI: threat category ID check
- Evidence:

### P2. Contracts and data model
- Status: not started. Depends on: P1.
- [ ] v1 schemas for four messages in `/contracts`
- [ ] Typed error schemas for five failure modes
- [ ] Migration-note convention
- [ ] Data model, constraints, indexes, migration tool, access control
- [ ] Verify: producer and consumer contract tests
- [ ] Verify: unbumped breaking change fails
- [ ] Verify: migration keeps data
- [ ] Verify: duplicate and incomplete inserts rejected
- [ ] CI: contract tests, schema diff, migration tests
- Evidence:

### P3. Seed attack suite and deterministic executor
- Status: not started. Depends on: P2, safety envelope.
- [ ] Case format with OWASP ID and boundary, invariant or regression tag
- [ ] Executor through the allowlist chokepoint
- [ ] Deterministic checks (canaries, PHI, patient-ID, tool allowlist)
- [ ] 3+ categories, synthetic fixtures
- [ ] Verify: dry run passes in CI
- [ ] Verify: one approved live run stored under `evals/`
- [ ] Verify: replay gives same verdict
- [ ] Verify: weakened target fails the checks
- [ ] CI: suite validation, synthetic-data scan, allowlist tests
- Evidence:

### P4. Judge prototype, Red Team seed
- Status: not started. Depends on: P3, P0 model ADR.
- [ ] Judge with deterministic rules then LLM for ambiguous cases
- [ ] Labeled ground-truth set, drift procedure
- [ ] Minimal Red Team under budget
- [ ] Cost metering and kill switch
- [ ] Verify: precision, recall, false-positive rate measured
- [ ] Verify: never approves a confirmed exploit as safe
- [ ] Verify: cap halts before next call
- [ ] Verify: one live run, stored traceable finding
- [ ] CI: Judge eval with recorded or stub responses
- Evidence:

### P5. MVP pack
- Status: not started. Depends on: P1 to P4.
- [ ] `ARCHITECTURE.md` with summary, diagram, agents, AI-use disclosure, API limits and auth
- [ ] README setup and run instructions
- [ ] Spend so far recorded
- [ ] Verify: fresh clone runs a dry-run campaign
- [ ] Verify: every MVP hard gate ticked against the PRD
- [ ] CI: documentation checks
- Evidence:

### P6. Orchestrator and multi-agent run
- Status: not started. Depends on: P2 to P4.
- [ ] Orchestrator reads coverage, findings, regressions
- [ ] Persisted run state, queue behavior if a queue exists
- [ ] Rate-limit handling, cost halt or redirect, no-priority fallback
- [ ] Regression trigger on target version change
- [ ] Verify: end-to-end trace under one correlation ID
- [ ] Verify: killed agent gives typed error and resumable state
- [ ] Verify: novelty measure
- [ ] CI: state-machine tests with scripted agents
- Evidence:

### P7. Regression harness, Documentation agent, human gates
- Status: not started. Depends on: P6.
- [ ] Versioned, queryable exploit store and regression cases
- [ ] Reappearance and cross-category regression detection
- [ ] Repeat runs, side-effect assertions
- [ ] Documentation agent with field and uniqueness validation, 3+ reports
- [ ] Human approval gates
- [ ] Verify: fixed then regressed sequence
- [ ] Verify: report reproduced by a reviewer
- [ ] Verify: false positive held
- [ ] CI: regression suite against stub target, report-format checks
- Evidence:

### P8. Observability, performance, load
- Status: not started. Depends on: P6, P7.
- [ ] Queryable answers to every PRD observability question
- [ ] Baselines for 100 cases plus full regression suite
- [ ] 100-case live load test (needs approval), bottleneck and fix
- [ ] Regression SLO and index documentation
- [ ] Verify: baselines committed
- [ ] Verify: SLO asserted in CI
- [ ] Verify: per-agent cost attribution
- [ ] CI: SLO assertion
- Evidence:

### P9. Platform security and CI completion
- Status: not started. Depends on: P2 onward.
- [ ] Coverage floor, mypy baseline, pip-audit, Bandit, self-scan
- [ ] Auth model, role-scoped database access
- [ ] Scheduled and target-change triggers with protected secrets
- [ ] Harmful-content handling, audit trail
- [ ] Verify: breaking PR fails CI
- [ ] Verify: off-allowlist target refused and logged
- [ ] Verify: no secrets exposed to fork PRs
- Evidence:

### P10. Required exercises and evidence
- Status: not started. Depends on: P6 to P9.
- [ ] Triage lab, 10+ findings with dispositions
- [ ] ATO-style evidence packet
- [ ] Integration packet, labeled peer or stub (Q4)
- [ ] Failure drills
- [ ] AI cost analysis at 100, 1K, 10K, 100K
- [ ] Verify: each drill yields its typed error
- [ ] Verify: projections use measured cost
- Evidence:

### P11. Final delivery
- Status: not started. Depends on: everything.
- [ ] Demo video, 3 to 5 minutes
- [ ] Social post tagging @GauntletAI
- [ ] Final README pass, deployed URL re-check
- [ ] Verify: line-by-line pass over the PRD submission table
- Evidence:

## Spend log

Record every paid call. The PRD asks for actual development spend.

| Date | Purpose | Provider and model | Approved cap (USD) | Actual (USD) | Notes |
|---|---|---|---|---|---|

## Log

| Date | Entry |
|---|---|
| 2026-10-17 | Roadmap revision 2, DECISIONS.md and PROGRESS.md created. No implementation started. |
| 2026-10-17 | P0 implemented locally in `agentforge-platform` (adapted plan in `P0_plan.md`). Checked on Python 3.10.13 only. Nothing committed or pushed. Reachability, Python 3.12 and GitHub Actions UNVERIFIED. |
| 2026-10-17 | Rechecked on Python 3.12.15, all local P0 checks pass. User ran four manual smoke tests (allowlist, budget, kill switch, missing OpenRouter attestation), reported successful. Target reachability remains deferred to P3. GitHub Actions remains UNVERIFIED until CI runs. |
| 2026-10-17 | P0 marked done. Commit `4bbd1b6` pushed to `origin/main`. GitHub Actions CI #1 passed (user-reported, not independently confirmed by the assistant). 74 automated tests and four manual smoke tests recorded. Target reachability stays deferred to P3 (exception to the update rule). Provider spend-limit attestation (Q13) is pending before live testing. Nothing committed for this edit. |
