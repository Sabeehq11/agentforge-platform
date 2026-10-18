# Week 3 progress

Tracks checkpoints P0 to P11. The plan is in [ROADMAP.md](ROADMAP.md). Decisions and open questions are in
[DECISIONS.md](DECISIONS.md). The Week 3 PRD is authoritative.

Update rule: a checkpoint is `done` only when every verification line under it has evidence recorded here (a command,
a file path or a result). Built without evidence is `in progress`. Nothing is marked done from memory.

Status values: `not started`, `in progress`, `blocked`, `done`.

## Milestones

| Milestone | Due (PRD) | Checkpoints | Status |
|---|---|---|---|
| Architecture Defense | 4 hours after kickoff | P0, drafts of P1 and P2 | P0 done (reachability still unverified), P1 done, P2 done |
| MVP | Tuesday 11:59 PM | P0 to P5 | not started |
| Final | Friday noon | P6 to P11 | not started |

The kickoff time is not recorded in the repo, so the Architecture Defense deadline is unconfirmed.

## Safety envelope (all must be done before the first live attack)

| Control | Status | Evidence |
|---|---|---|
| Target allowlist, default deny, one HTTP chokepoint | in progress | Chokepoint, refusal log and header/body transport exist. `config/allowlist.yaml` is still empty. No live transport |
| Target identity check | in progress | Fingerprint check and fake login-page GET exist. The read-only GET of the running login page was not made. E-3 stays partial |
| Synthetic-data fixtures and transcript scan | in progress | Synthetic fixtures and the PHI scan exist and are tested. No live transcript has been stored |
| Per-run and per-day USD caps, attack-count cap, approval token | in progress | `budget.py` and tests in P0. Not approved for any run |
| Provider-side spending limit on every key (DECISIONS Q13) | in progress | Attestation gate in P0 refuses while `spend_limits.yaml` is empty. Limits not set |
| Per-agent cost metering and kill switch | in progress | Kill switch in `budget.py`. P4 ledger separates reserved and incurred for `red_team`, `judge` and fixture `target`. Not exercised on a live run |
| Request-rate cap toward the target | in progress | `rate.py` and tests. A 429 is not retried. Not exercised against the running target |
| Human approval for over-cap runs, new allowlist entries, load tests | not started | |

## PRD traceability

The full requirement-to-checkpoint matrix, with status and evidence, is [PRD_TRACEABILITY.md](PRD_TRACEABILITY.md).
The audit of P0, P1 and P2 is in that file, including the P1 and P2 closure audits. Two gaps are flagged and not fixed here,
because neither is a small edit: no deployed URL is recorded (G-1, Q2), and the build-versus-configure tool claims
are unverified (G-2).

## Deliverables (PRD submission table)

| Deliverable | Needed at | Status | Notes |
|---|---|---|---|
| Deployed target URL | every checkpoint | not started | Quick tunnel URL rotates (Q2) |
| GitHub repo with setup guide and run instructions | MVP | in progress | Layout decided: independent repo (ADR-001). README is P0-level |
| `THREAT_MODEL.md` | MVP | done for P1 | Written at repo root. Defenses are by code reading, not tested |
| `USERS.md` | MVP **(unconfirmed)** | done for P1 | Written at repo root. Checkpoint unconfirmed (Q5) |
| `ARCHITECTURE.md` | MVP | not started | P5 |
| `/contracts` | MVP first version | done for P2 | v1 schemas in `contracts/v1/`. Full coverage of both sides is Final |
| `evals/` with 3+ categories of results | MVP | not started | P3 suite exists locally. No graded target result, so H-3 stays unmet |
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
- Status: **done**, with the evidence below. Depends on: P0.
- [x] `THREAT_MODEL.md` with ~500-word summary (543 words, within the checker's 450-550 band)
- [x] Six PRD categories with surface, impact, difficulty, existing defenses (25 subcategory IDs, each with all four)
- [x] OWASP Top 10 and LLM Top 10 mapping, non-applicable items explained (D-013; no attacker-controlled outbound URL construction identified for SSRF at the pinned SHA, which is not proof it is impossible). List names verified against the official pages on 2026-10-17, links recorded in THREAT_MODEL.md. Two CareTeam authorization weaknesses recorded there as P3 candidates.
- [x] Platform-side threats (`TM-PL-1` to `TM-PL-6`)
- [x] `USERS.md`
- [x] Verify: defenses cited to files (spot-checked against the pinned SHA, see evidence)
- [x] CI: threat category ID check (`scripts/check_threat_model.py`, wired into `.github/workflows/ci.yml`)
- [x] Three manual checks recorded (closure audit 2026-10-17, against the original 17-page PRD):
  1. Each of the six categories has attack surface, impact, difficulty and defense status. Checker: 25 subcategory
     IDs, 0 problems, plus a read of the sections.
  2. Every cited defense path exists at `9f03654`. File list in the evidence below. By code reading, not tested.
  3. All 20 OWASP rows are present, each mapped or marked not applicable or out of scope with a reason. Names
     checked against the official pages.
- Evidence, 2026-10-17, Python 3.12.15, venv under `/tmp`:
  - Target source was read at `9f036541cf95e896db065e0c652afb75627b03c2` through read-only fetches to a temp directory.
    No request was made to the deployed target, no model was called, and nothing was spent.
  - `scripts/check_threat_model.py`: 25 subcategory IDs, 11 references, 0 problems.
  - Every defense citation was spot-checked against the fetched tree: `agent/app/gateway.py`, `signing.py`, `authz.py`,
    `loop.py`, `tools.py`, `verifier.py`, `prompts.py`, `conversation.py`, `chat.py`, `audit.py`, `rules.py`,
    `advice.py`, `w2/api.py`, `w2/vlm.py`, `w2/ingest.py`, `w2/store.py`, `w2/verify.py`, `w2/synthesis.py`,
    `w2/supervisor.py`, `agent/AUTHZ_PROOF.md`, and the module's `public/chat.php`, `upload.php`, `source.php`,
    `src/UserTokenIssuer.php`, `public/assets/copilot.js`. All present at the pin. The SSRF conclusion comes from
    listing every `httpx` call site in `agent/app` and finding each URL built from settings plus a fixed path.
  - Local CI command set, rerun 2026-10-17 on Python 3.12.15 (venv under `/tmp`, pinned tools): ruff clean, mypy clean
    (7 files), `pytest --cov-fail-under=85` 84 passed at 96.26% coverage, Bandit clean, secret scan 0 hits, link check
    34 links and 0 problems, workflow guard 0 problems, ADR check 7 ADRs and 0 problems, threat-model check 0 problems.
    GitHub Actions has not run on these files: **UNVERIFIED** until the user pushes.
  - Closure audit, 2026-10-17, against the original Week 3 PRD, the roadmap and `Docs/PRD_TRACEABILITY.md`. P1-owned
    requirements (H-2, S-2, S-3, S-4, and the mapping half of E-11) are met. All 69 requirement rows have a checkpoint
    owner. Unresolved, and not P1's to fix: G-1 (no deployed URL), G-2 (unverified tool claims), plus S-1, G-5 and
    E-6. The P0 progress edit is in its own commit. GitHub Actions stays UNVERIFIED until this commit is pushed and CI runs.

### P2. Contracts and data model
- Status: done. Depends on: P1. No agent is implemented. D-1 stays partial until the P7 store. D-7 and D-8 stay partial until P7 and P9 enforcement.
- [x] v1 schemas for four messages in `/contracts`
- [x] Typed error schemas for five failure modes
- [x] Migration-note convention
- [x] Data model, constraints, indexes, migration tool, access control
- [x] Verify: producer and consumer contract tests
- [x] Verify: unbumped breaking change fails
- [x] Verify: migration keeps data
- [x] Verify: duplicate and incomplete inserts rejected
- [x] CI: contract tests, schema diff, migration tests
- Evidence, 2026-10-17, Python 3.12.15 at `/private/tmp/p2pin/bin/python`. No request to the target, no model call, no spend:
  - Nested contract tests: `pytest tests/test_contracts_nested.py` — 16 passed. Missing required field, wrong type, invalid enum and extra property, each inside a nested object and an array item.
  - Unversioned breaking change: a temporary git repo whose v1 schema dropped a required field. `scripts/check_schema_diff.py` printed `BREAKING` and exited 1. The temporary repo was outside this tree. No tracked file was edited.
  - Migration: a temporary SQLite file, one exploit inserted through `insert_exploit`, then fixture migration `0002` applied through `migrate`. The original nine columns were unchanged and the new column was `unspecified`.
  - Duplicate and incomplete inserts, on a temporary database: `DuplicateSequence: an exploit with this attack sequence already exists` and `IncompleteRecord: missing required field: reproduction_steps`. Neither was a `sqlite3.Error`. The exploits table still held one row.
  - Source scan of `src/agentforge/agents/`, `src/agentforge/store/` and `src/agentforge/contracts/`: no `httpx`, `openai`, `anthropic`, `socket`, `urllib` or `requests` import.
  - Local CI command set: ruff clean, mypy clean, `pytest --cov=agentforge --cov-fail-under=85` 145 passed at 95.79% coverage, Bandit clean, secret scan, link check, ADR check, threat-model check, workflow guard and schema diff. Schema diff exits 0 while `contracts/v1` has no committed baseline, which is what the script says when there is nothing to compare. GitHub Actions has not run on these files: **UNVERIFIED** until the user pushes.
  - Closure audit, 2026-10-17, against the original Week 3 PRD (pages 11–12), [ROADMAP.md](ROADMAP.md) section 4 P2 and [PRD_TRACEABILITY.md](PRD_TRACEABILITY.md). C-1 to C-5, D-6 and D-9 met. D-1's P2 model is complete; the row stays partial until P7. D-7 and D-8 stay partial. No later-checkpoint row was implemented or marked met. G-1 to G-6 remain. G-3 is resolved by `contracts/v1/` and is not deleted. Nothing committed or pushed.

### P3. Seed attack suite and deterministic executor
- Status: in progress. Depends on: P2, safety envelope. Not done: the approved live run has not been started, so H-3 has no graded target result. The Stage 3 live-agent sentence is partial until P4. H-4 is not moved.
- [x] Case format with OWASP ID and boundary, invariant or regression tag
- [x] Executor through the allowlist chokepoint
- [x] Deterministic checks (canaries, PHI, patient-ID, tool allowlist)
- [x] 3+ categories, synthetic fixtures
- [x] Verify: dry run passes in CI
- [ ] Verify: one approved live run stored under `evals/`
- [x] Verify: replay gives same verdict
- [x] Verify: weakened target fails the checks
- [x] CI: suite validation, synthetic-data scan, allowlist tests
- Local integration path, 2026-10-18, fake transport only. Not a live run and not evidence for H-3. `src/agentforge/evals/session.py` can GET the login page, POST a synthetic fixture login, read `data-csrf` and `data-endpoint`, and POST chat JSON with `X-CSRF-Token`. The pinned SHA `9f036541cf95e896db065e0c652afb75627b03c2` shows no authorized public-module step that sets the open patient, so no set-pid URL was added. Without a caller-supplied verified workflow, chat cases stay `not_run`. TM-EX-2 and TM-PI-2 stay `not_run`. TM-DS-3 stays a local cap stop and does not contact the target. A fake `401` grades `pass` for TM-EX-3; a fake `200` body grades `fail`; a fake `409` is `error`. `LIVE_ENABLED` remains false. `real_transport` raises before any socket and does not open one. No hostname was written into `config/allowlist.yaml`.
- Evidence, 2026-10-17, Python 3.12.15 at `/private/tmp/p2pin/bin/python`. No request to the target, no model call, no spend. `LIVE_ENABLED` remains false. `config/allowlist.yaml` remains empty. `config/spend_limits.yaml` remains empty:
  - Suite: six cases in `evals/cases/`, categories TM-PI, TM-EX, TM-DS. `scripts/check_evals.py` printed `OK 6 cases` and exited 0. A dry-run with no budget writes `not_run` for every case. With an approved budget, only `seed-tm-ds-3` is `pass` (the local attack-count stop). No target case is `pass`.
  - Replay: the same recorded transcript graded `pass` twice. A transcript that obeys `CANARY-AF-PI1` graded `fail`. An inconclusive patient-boundary transcript graded `error`, not `pass`.
  - Weakened stub: a local response that echoes the canary graded `fail`. No request to the pinned target.
  - Kill switch: `AGENTFORGE_LIVE=1` still left the transport uncalled and the case `not_run`.
  - Envelope tests in `tests/test_p3_envelope.py`: off-list URL and off-list redirect logged and refused; rate cap stopped before the next call; identity check rejected a body without `OpenEMR` and rejected a redirect; a PHI pattern refused the results write.
  - Local CI command set passed: ruff, mypy, pytest (coverage above the 85% floor), Bandit, secret scan, link check, ADR check, threat-model check, workflow guard, schema diff, `scripts/check_evals.py`. GitHub Actions has not run on these files: **UNVERIFIED** until the user pushes.
  - Not run, and not marked done: operator steps 1–5 and 8 of the P3 plan. No URL was supplied. No live login-page GET. No approved live suite run. Reachability stays UNVERIFIED. G-1 and E-6 stay open.
  - Closure audit, 2026-10-17, against the original Week 3 PRD Stage 3, [ROADMAP.md](ROADMAP.md) section 4 P3 and [PRD_TRACEABILITY.md](PRD_TRACEABILITY.md). E-8, E-9, E-12 and the case-mapping half of E-11 are met by the suite and tests. H-3 is not met: there is no graded `pass` or `fail` from a target run in three categories. The Stage 3 live-agent sentence is recorded as partial until P4. H-4 stays owned by P4 and is not marked met. No requirement row was added or moved.
- Evidence, 2026-10-18, Python 3.12.15 at `/private/tmp/p2pin/bin/python`. Local implementation and local CI only. No request to the target, no model call, no spend. `LIVE_ENABLED` remains false. `config/allowlist.yaml` remains `entries: []`. `config/spend_limits.yaml` remains `attestations: []`. No hostname was written into the repo.
  - Completed locally: the seed suite, deterministic executor, refusal log, rate cap, PHI scan, and the public-module session path in `src/agentforge/evals/session.py`. Fake tests cover identity mismatch (no later call), chat withheld without confirmed patient context, CSRF and question on a confirmed-context POST, cookie absent from the refusal log, TM-PI-3 conversation ids, and TM-EX-3 grading (`401` pass, `200` body fail, `409` error). TM-EX-2 and TM-PI-2 stay `not_run`. TM-DS-3 stays a local cap stop.
  - Local CI, same command set as `.github/workflows/ci.yml`, all exit 0: ruff, mypy (25 source files), pytest **187 passed, 91.54% coverage** (floor 85%), Bandit, secret scan (0 hits), link check (78 links, 0 problems), ADR check (7, 0 problems), threat-model check (0 problems), contract tests (54 passed), schema diff (11 schemas, 0 breaking), workflow guard, `scripts/check_evals.py` (`OK 6 cases`), and the synthetic-data and allowlist pytest step (72 passed). Ruff was rerun with `--no-cache` because the read-only sandbox could not write `.ruff_cache`; that rerun passed.
  - GitHub Actions has not run on these files: **UNVERIFIED** until the user pushes.
  - Still open, and not closed by this evidence: the approved live run under `evals/` (checkbox above stays unchecked). H-3 stays unmet. H-4 and the Stage 3 live-agent sentence stay partial until P4. G-1, E-6, and the live half of E-3 stay open. S-1 stays partial until the running stack is confirmed equal to `9f03654`. E-1 stays partial because the allowlist is empty. No row in [PRD_TRACEABILITY.md](PRD_TRACEABILITY.md) was marked met by this pass. Nothing committed or pushed.

### P4. Judge prototype, Red Team seed
- Status: in progress. Depends on: P3, P0 model ADR. Not done: H-4, M-12, M-3, M-4, and E-7 stay open on the evidence bars in [PRD_TRACEABILITY.md](PRD_TRACEABILITY.md). H-3 stays unmet and owned by P3. No row was moved.
- [x] Judge with deterministic rules then LLM for ambiguous cases
- [x] Labeled ground-truth set, drift procedure
- [x] Minimal Red Team under budget
- [x] Cost metering and kill switch
- [x] Verify: precision, recall, false-positive rate measured
- [x] Verify: never approves a confirmed exploit as safe
- [x] Verify: cap halts before next call
- [ ] Verify: one live run, stored traceable finding
- [x] CI: Judge eval with recorded or stub responses
- Evidence, 2026-10-18, Python 3.12.15 at `/private/tmp/p2pin/bin/python`. No request to the target, no model call, no spend. `LIVE_ENABLED` remains false. `config/allowlist.yaml` remains empty. `config/spend_limits.yaml` remains empty. `config/models.yaml` remains `TBD`:
  - Judge: `src/agentforge/agents/judge.py`. Families are loaded from `config/models.yaml` through `load_models`. A config where Red Team and Judge share a family is refused. A verdict requires a `recorded_transcript` that `validate()` accepts and that `recorded_by` is `executor`. `judge()` with only an `AttackResult` returns `no_findings_in_window` and no verdict. An attacker `observed_behavior` of `fail` does not override a transcript the canary grader marks `pass`. A transcript the canary grader marks `fail` returns a draft `ConfirmedExploit` and does not call the stub, including when the stub would say `pass` and the claim says `pass`.
  - Labeled set: three synthetic items in `evals/judge/labeled/` (`benign` and `near_miss`). Positive class is `fail`. `assert_no_drift` compares those rates to `evals/judge/baseline.json` and raises on a drop. A constructed drop (recall below the file) raises `LabelRejected`. Drift procedure: `Docs/JUDGE_DRIFT.md`. These rates are stub-mode, not a provider evaluation.
  - Red Team seed: `src/agentforge/agents/red_team.py` mutates one existing seed through the ledger. The mutation is a suffix, a trailing space, and the original turn copied once. After `Budget.kill()`, `propose` returns `budget_exceeded`, `mutations` stays 0, and neither reserved nor incurred is written. At the attack-count cap the next `propose` returns `budget_exceeded` and does not increment `mutations`.
  - Ledger: migration `0002` adds `agent_spend` with separate `reserved_usd` and `incurred_usd`. The reserved row is written before `Budget.reserve`; a refusal deletes it. `release` returns the amount to the budget and leaves incurred at 0. A refused stub releases the Judge reservation and does not incur. `Ledger.combined` raises rather than adding the two columns. Target-side amounts in tests are fixtures. No usage API was called.
  - Probe: `Docs/MODEL_PROBE.md` records `not run against a provider`. `evals/judge/probe/candidates.json` is placeholders. M-12 stays not started.
  - Local CI after the ledger fix, 2026-10-18: ruff exit 0, mypy exit 0 (30 source files), pytest 213 passed, 90.48% coverage (floor 85%), Bandit exit 0, `pytest tests/test_p4_judge.py` 25 passed. GitHub Actions has not run on these files: **UNVERIFIED** until the user pushes.
  - Still open, and not closed by this evidence: the approved live run and its stored finding (checkbox above stays unchecked). H-4 stays unmet. H-3 stays unmet and owned by P3. G-1, E-6, and the live half of E-3 stay open. No hostname was written. Nothing committed or pushed.
  - Gap closure, 2026-10-18, local only. No target request, no provider call, no spend. `LIVE_ENABLED` remains false. Allowlist and spend attestation remain empty. `config/models.yaml` remains `TBD`.
    - Local CI after the gap closure: ruff exit 0, mypy exit 0 (30 source files), pytest 216 passed, 90.45% coverage (floor 85%), Bandit exit 0, schema diff 0 breaking, link check 0 problems, `pytest tests/test_p4_judge.py` 28 passed. GitHub Actions has not run on these files.
    - Metric test: an `error_code` is not scored as `fail`. A draft exploit is still a confirmed fail. `tests/test_p4_judge.py`.
    - Category criteria: TM-PI-1, TM-PI-2, TM-PI-3, TM-EX-2, TM-EX-3, and TM-DS-3 each use their existing grader. Optional `attacks_before`, `attacks_after`, and `attack_cap` were added to `recorded_transcript`. A subcategory with no bound grader is uncertain.
    - Escalation: optional `needs_human_review` on Verdict v1. A stub `partial` sets it and stores no exploit. `judge_timeout` stays an error with `detail` `needs_human_review`. It is not converted to a partial verdict. The reservation is released.
    - Drift: `label-drift-quote` was hand-labeled `pass` before judgment. The stub Judge returned `fail`. Review is in [JUDGE_DRIFT.md](JUDGE_DRIFT.md). The fixture was corrected. The label was not. The re-score changed `labeled` from 3 to 4. Rates stayed 1.0, 1.0, and 0.0. The baseline records that count. It was not edited to pass CI.
    - Ownership, unchanged: M-3 partial until two graded target versions match. M-4 partial until a provider Judge is checked. E-7 partial until a live run records an operator-supplied target-side amount. M-12 unmet until an approved probe replaces the fixture candidates and `config/models.yaml` leaves `TBD`. H-3 unmet, owned by P3. H-4 unmet until a live agent run stores a traceable finding. Stage 3 stays unmet until H-3 and H-4 are both met.

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
| 2026-10-17 | P1 implemented: `THREAT_MODEL.md`, `USERS.md`, `scripts/check_threat_model.py` and its tests, one CI step added. Q8 resolved as D-013 (no attacker-controlled outbound URL construction identified for SSRF at the pinned SHA, not proof it is impossible). No target request, no model call, no spend. Nothing committed or pushed. |
| 2026-10-17 | P1 corrections: summary trimmed to 543 words (450-550 band restored in the checker) and the SSRF wording qualified in THREAT_MODEL.md and D-013. Checker and its 10 tests rerun, all passing. Nothing committed or pushed. |
| 2026-10-17 | PRD traceability matrix written at `Docs/PRD_TRACEABILITY.md`. P0 and P1 audited against it. No requirement fix was small enough to make: the deployed URL (G-1) and the unverified tool claims (G-2) are flagged. Nothing committed or pushed. |
| 2026-10-17 | OWASP names in THREAT_MODEL.md checked against the official 2021 Web and 2023 v1.1 LLM pages. Both match; one hyphenation corrected (A10); UNVERIFIED labels removed and the source links recorded. Two CareTeam authorization weaknesses from the P1 code review recorded as P3 candidates. No model or target call. Nothing committed or pushed. |
| 2026-10-17 | P1 closure audit against the original 17-page PRD, the roadmap and `Docs/PRD_TRACEABILITY.md`. P1-owned requirements met. Three manual checks recorded. All 69 requirement rows have a checkpoint owner. G-1 and G-2 remain unresolved, with S-1, G-5 and E-6. P1 judged ready to commit. No model or target call. |
| 2026-10-17 | P2 closure audit recorded. C-1 to C-5, D-6 and D-9 met. D-1, D-7 and D-8 stay partial. Six manual checks recorded: 16 nested tests passed, schema diff exit 1, migration preserved its row, typed insert errors, no network client in the new packages, 145 tests at 95.79% coverage. G-1 to G-6 unchanged. G-3 resolved, not deleted. Nothing committed or pushed. |
| 2026-10-17 | P3 seed suite and deterministic executor implemented. Six synthetic cases, dry-run default, refusal log, identity check, rate cap and PHI scan. `LIVE_ENABLED` stays false and is not bypassable by an env flag. No target request, no model call, no spend. Live run not started. Nothing committed or pushed. |
| 2026-10-18 | P3 public-module session path added and tested with fakes only. Identity mismatch makes no later call. Chat is not sent unless patient context is confirmed by an injected verified workflow; the pinned source shows none, so those cases stay `not_run`. TM-EX-2, TM-PI-2 stay `not_run`. TM-DS-3 stays local. H-3, H-4, G-1, E-3 live half and E-6 stay open. No target request, no model call, no spend. Nothing committed or pushed. |
| 2026-10-18 | P3 local CI recorded: 187 tests passed, 91.54% coverage, and every workflow check exited 0. Local implementation is recorded. Live execution, H-3, H-4, G-1, E-3 live half, E-6 and S-1 stay open. No PRD traceability status was changed. No target request, no model call, no spend. Nothing committed or pushed. |
