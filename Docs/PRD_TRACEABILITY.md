# PRD traceability

Every applicable engineering requirement in the Week 3 PRD, the checkpoint that owns it, and the evidence that exists
today. The PRD is authoritative. This file is the checklist [ROADMAP.md](ROADMAP.md) section 7 summarizes. Status is
updated as checkpoints land. A row is `met` only when the evidence column names a file or a recorded result.

Status values: `met`, `partial`, `not started`, `gap`, `deferred`, `unconfirmed`.

- `gap` means a finished checkpoint owns the requirement and it is not satisfied. These are listed in the audit below
  and are not fixed by widening scope.
- `deferred` means a decision moved it, with the decision named.
- `unconfirmed` means the PRD does not say when it is due, or whether it applies. See [DECISIONS.md](DECISIONS.md).

Nothing here is a test result against the running target. No request was made to the target to write this file.

## Audit of P0 and P1 (2026-10-17)

Checked against the requirements assigned to them below and against the files in the working tree.

P0 meets its roadmap verification list, with the recorded exception that reachability is deferred to P3 (D-012). It
does not meet the PRD hard gate that a deployed URL is submitted with every checkpoint. That is a gap, and it is not
fixable from this repo: no current URL is known, the tunnel hostname rotates (Q2), and this work makes no request to
the target.

P1 meets the Stage 2 hard gate. `THREAT_MODEL.md` exists, starts with a 543-word summary, and gives all four
attributes for each of the six categories. The OWASP mapping is present. Case-level OWASP mapping is a P3 requirement
and is not a P1 miss.

| Id | Checkpoint | Finding | Treatment |
|---|---|---|---|
| G-1 | P0, every later checkpoint | No deployed URL is recorded or submitted. PRD hard gate. | Flagged. Needs the operator to supply the current URL and a decision on Q2. Not invented here |
| G-2 | P0 | Build-versus-configure tool claims are marked unverified. The PRD asks what each tool covers and where it falls short | Flagged. Checking the claims means reading each vendor's docs, which is a separate approved step, not a small edit |
| G-3 | P0 | Evidence packet message schemas are names, not JSON Schemas | Not a gap. Resolved at P2: the schemas are in `contracts/v1/`. Kept so the P0 finding stays visible |
| G-4 | P0 | Off-list refusals are raised, not logged. ROADMAP 2.2 says refused and logged | Resolved at P3. `src/agentforge/safety/refusal_log.py` logs gate, host and a fixed reason. `test_off_list_url_is_logged_and_refused` and `test_off_list_redirect_is_logged_and_not_followed`. Row kept |
| G-5 | P0 | CODEOWNERS has no effect until branch protection requires it. That setting is not confirmed | Flagged. A repository setting, not a code change |
| G-6 | P1 | None found against the P1 requirements | No P1 code or doc fix was needed. Closure audit 2026-10-17 agrees |

## P1 closure audit (2026-10-17)

Re-read the original Week 3 PRD (`Week_3_AgentForge_Updated.docx.pdf`, 17 pages), [ROADMAP.md](ROADMAP.md) section 4
P1, and this matrix. No requirement was added or moved. The only status changes are in the evidence column of H-2
and E-11, both already owned by P1.

**P1-owned requirements are met.** H-2, S-2, S-3, S-4 and the P1 half of E-11. The PRD Stage 2 list is covered:
direct, indirect and multi-turn injection (`TM-PI-1` to `TM-PI-3`); PHI leakage, cross-patient exposure and
authorization bypass (`TM-EX-1` to `TM-EX-3`); conversation history and context poisoning (`TM-SC`); unintended tool
invocation, parameter tampering and recursive calls (`TM-TM`); token exhaustion, loops and cost amplification
(`TM-DS`); privilege escalation, persona hijacking and trust-boundary violation (`TM-ID`). Each subcategory has the
four attributes. The five target-specific surfaces from the roadmap are in the surfaces table.

**P0-owned requirements are not all met, and P1 does not close them.** G-1 (H-1) and G-2 (S-5) are unresolved. So
are S-1 (the running stack is not confirmed equal to the pin), G-5 (E-2, branch protection), and E-6 (provider
spend limits, before the first live run, Q13). E-1 and E-4 are skeletons, which is what P0 scoped. None of these is
a P1 miss, and none is fixed here.

**Three P1 manual checks, all recorded in [PROGRESS.md](PROGRESS.md):**

1. Category completeness: each of the six categories has attack surface, impact, difficulty and defense status,
   confirmed by `scripts/check_threat_model.py` (25 subcategory IDs, 0 problems) and by reading the sections.
2. Defense citations: every cited path exists at `9f036541cf95e896db065e0c652afb75627b03c2`. The file list is in
   the P1 evidence. Citations are by code reading, not by a test against the running target.
3. OWASP coverage: all 20 rows present, each mapped or marked not applicable or out of scope with a reason. Names
   checked against the official pages on 2026-10-17. SSRF is a reading of the pinned code, not proof it is
   impossible.

**All 69 requirement rows have a checkpoint owner.** Counted: H-1 to H-5, S-1 to S-7, M-1 to M-12, D-1 to D-13, C-1 to C-7,
E-1 to E-16, X-1 to X-9. D-11's owner is conditional (P6, only if a queue is used) and C-7's applicability is
unconfirmed; both still name a checkpoint.

**P1 is ready to commit, with the conditions in [PROGRESS.md](PROGRESS.md).** It is not committed here. GitHub
Actions has not run on these files.

## P2 closure audit (2026-10-17)

Re-read the original Week 3 PRD (`Week_3_AgentForge_Updated.docx.pdf`, pages 11–12), [ROADMAP.md](ROADMAP.md) section 4
P2, and this matrix. No requirement was added or moved. No P3–P11 row was implemented or marked met.

**P2-owned requirements are met.** C-1, C-2, C-3, C-4, C-5, D-6 and D-9. The four v1 message schemas and the five
typed error schemas are in `contracts/v1/`. Producer and consumer tests, the nested rejection tests and the schema-diff
check are recorded in [PROGRESS.md](PROGRESS.md). The migration note is [migrations/0001-initial-schema.md](migrations/0001-initial-schema.md),
and the log row is in [DECISIONS.md](DECISIONS.md) section 5.

**Three shared rows stay partial, and that is the planned split.** D-1's P2 data model is complete (`schema.sql`,
indexes, `schema_migrations`); the store agents write is P7. D-7 has the unique id, required fields and sequence-hash
constraint; Documentation-agent enforcement is P7. D-8 has the design record and the insert path refuses `published`;
role-scoped enforcement is P9.

**P0 and P1 findings are not closed by P2.** G-1, G-2, G-4, G-5 and G-6 stand as written. G-3 is resolved: the packet
now points at `contracts/v1/` instead of names only. The row is kept, not deleted. S-1, E-2 and E-6 are unchanged.

**Six P2 manual checks, all recorded in [PROGRESS.md](PROGRESS.md):**

1. Nested validation: 16 tests passed in `tests/test_contracts_nested.py`.
2. An unversioned breaking schema change was rejected with exit 1.
3. A fixture migration kept the inserted exploit and filled the new column.
4. A duplicate sequence raised `DuplicateSequence`. A missing required field raised `IncompleteRecord`. Neither was a
   raw `sqlite3` error.
5. No HTTP client, model SDK or socket import under `src/agentforge/agents/`, `store/` or `contracts/`.
6. The local CI command set passed: 145 tests, 95.79% coverage. GitHub Actions has not run on these files.

**All 69 requirement rows still have a checkpoint owner.** None was moved.

## P3 closure audit (2026-10-17)

Re-read the original Week 3 PRD (`Week_3_AgentForge_Updated.docx.pdf`, Stage 3 and the eval-design paragraph),
[ROADMAP.md](ROADMAP.md) section 4 P3, and this matrix. No requirement was added. No owner was changed. No P4–P11
row was implemented or marked met.

**What P3 met, with evidence in [PROGRESS.md](PROGRESS.md).** E-8, E-9, E-12, and the per-case half of E-11. Six
synthetic cases in `evals/cases/` cover TM-PI, TM-EX and TM-DS. Each has an OWASP id and one of `boundary`,
`invariant` or `regression_risk`. Dry-run writes `not_run` unless the local attack-count grader actually ran.
Replay of one transcript is stable. A weakened local stub fails the canary. An env flag cannot call the transport
while `LIVE_ENABLED` is false.

**H-3 is not met.** The suite exists. There is no stored graded `pass` or `fail` from a target run in three
categories. `not_run` does not count. The approved live run was not started: no URL, empty allowlist, empty spend
attestation.

**The PRD Stage 3 live-agent sentence is partial until P4.** The hard gate asks for `evals/` results from at least
three categories and one agent role live against the deployed target. The suite half is P3 and is not yet met (H-3).
The agent half stays owned by P4 (H-4). P3 does not implement Red Team, Judge, Orchestrator or Documentation, and
does not mark H-4 met. Status of that sentence is `partial`, not a moved row.

**Still open, and not closed here.** G-1 (no deployed URL). G-2. G-5. E-6 (spend attestation empty). S-1 (running
stack not confirmed equal to the pin). E-1 stays partial: the chokepoint, refusal log and rate cap exist, and
`config/allowlist.yaml` is still empty. E-3 is partial: the identity check exists and is tested against a stub
body; the read-only login-page GET was not made. G-4 is resolved by the refusal-log tests and is not deleted.

**Operator steps not run.** Allowlist edit, spend attestation, login-page GET, fixture-user confirmation, approved
live run, off-list host against a real transport. GitHub Actions has not run on these files.

**Local path added 2026-10-18. Not a closure.** `src/agentforge/evals/session.py` and the widened chokepoint can carry
headers and a body, and fake tests cover identity GET, login, CSRF, SSE parse, and TM-EX-3 grading. That is local
evidence only. It does not meet H-3: no graded target result was stored. H-4 stays unmet and owned by P4. G-1 stays
open: no deployed URL was written into the repo. E-3 stays partial: the login-page GET was not made against the
running target. E-6 stays a gap: `config/spend_limits.yaml` is still empty. S-1 stays partial until the running stack
is confirmed equal to `9f03654`. The pinned source shows no authorized public step that sets patient context, so
TM-EX-2 and TM-PI-2 stay `not_run` rather than a guessed patient-open or upload. No row below was marked met by this
pass.

**All 69 requirement rows still have a checkpoint owner.** None was moved.

## Hard gates

| Id | PRD requirement | Checkpoint | Status | Evidence |
|---|---|---|---|---|
| H-1 | Deployed target URL submitted with every checkpoint | P0, then every checkpoint | gap | No URL in [TARGET_FREEZE.md](TARGET_FREEZE.md). Q2 open. G-1 |
| H-2 | `THREAT_MODEL.md` with a ~500-word summary first, six categories, four attributes each | P1 | met | [THREAT_MODEL.md](../THREAT_MODEL.md). Summary 543 words. `scripts/check_threat_model.py`: 0 problems. Closure audit 2026-10-17 |
| H-3 | `evals/` with results from at least three attack categories | P3 | not started | Suite exists: `evals/cases/`, six cases, TM-PI, TM-EX, TM-DS. No graded target result. Dry-run is `not_run` except the local cap stop. A file of `not_run` does not meet this row. The 2026-10-18 session client is local fake evidence only and does not close this row |
| H-4 | One agent role running live against the deployed target | P4 | not started | No agent implemented. Stage 3 live-agent sentence is partial until P4 and is not moved here. `LIVE_ENABLED` is false |
| H-5 | `ARCHITECTURE.md` with a ~500-word summary, each agent named, a diagram | P5 | not started | Draft diagram only, in [DEFENSE_PACKET.md](DEFENSE_PACKET.md) |

## Stage deliverables

| Id | PRD requirement | Checkpoint | Status | Evidence |
|---|---|---|---|---|
| S-1 | Target stood up, changes to reach a testable state documented | P0 | partial | Pin, tree equality and "no changes by this repo" in [TARGET_FREEZE.md](TARGET_FREEZE.md). The running stack is not confirmed equal to the pin |
| S-2 | Attack surface map, including the five target-specific surfaces | P1 | met | [THREAT_MODEL.md](../THREAT_MODEL.md), surfaces table and `TM-PI` to `TM-ID` |
| S-3 | Platform-side threats (a target response or a transcript steering the Judge or Documentation agent) | P1 | met | `TM-PL-1`, `TM-PL-2` |
| S-4 | `USERS.md`: users, workflows, use cases, why automation | P1 | met | [USERS.md](../USERS.md). Due checkpoint unconfirmed (Q5); written at P1 anyway |
| S-5 | Build-versus-configure record before any agent: Burp, ZAP, Semgrep, Garak, commercial platforms, and why custom code is or is not justified | P0 | partial | [BUILD_VS_CONFIGURE.md](BUILD_VS_CONFIGURE.md) covers each named tool plus promptfoo, PyRIT and deterministic tooling. Claims are unverified. G-2 |
| S-6 | Architecture Defense evidence packet: diagram, message schemas, trust boundaries, failure modes | P0 | met as a draft | [DEFENSE_PACKET.md](DEFENSE_PACKET.md). JSON Schemas now published at `contracts/v1/` (G-3 resolved, row kept). The packet is still a draft, not `ARCHITECTURE.md` |
| S-7 | Independent code repo, setup guide, deployed link, run instructions | P0 layout, P5 guide | partial | ADR-001. README has setup for what exists. Deployed link is G-1. Run-against-target instructions are P5, because there is nothing to run yet |

## Multi-agent system

| Id | PRD requirement | Checkpoint | Status | Evidence |
|---|---|---|---|---|
| M-1 | Distinct agents, not a single agent or a pipeline. Each has inputs, outputs, trust level | P5 to define, P6 to run | not started | Named in the draft diagram only |
| M-2 | Novel attack generation, mutation of partial successes, multi-turn sequences | P4 seed, P6 full | not started | |
| M-3 | Judge independent of attack generation, consistent criteria across runs and versions | P4 | not started | Independence is a decision only: ADR-004, `src/agentforge/models_config.py` |
| M-4 | Judge ground truth, and a documented way to detect and correct drift | P4 | not started | |
| M-5 | Orchestrator reads coverage gaps, open findings and regressions, and picks the next campaign | P6 | not started | |
| M-6 | Halt or redirect when spend produces no signal | P6 | not started | Per-call caps and a kill switch exist (E-4, E-5). The signal-based redirect does not |
| M-7 | Regression run triggered when the target version changes | P6 | not started | |
| M-8 | Fallback when the Orchestrator has no priority | P6 | not started | |
| M-9 | Documentation agent produces the six report fields, reproducible by an engineer who was not there | P7 | not started | Fields are named in the draft packet only |
| M-10 | Minimum three distinct vulnerability reports | P7 | not started | MVP timing unconfirmed (Q5) |
| M-11 | Human approval before publishing critical or high findings and before any remediation. Agents propose a patch and never apply one | P7 | not started | Stated as a rule in [DEFENSE_PACKET.md](DEFENSE_PACKET.md). Not enforced in code |
| M-12 | Model per role chosen with refusal and cost considered | P4 | not started | ADR-004 defers the choice to a budgeted probe. No probe has been run |

## Regression, observability, data

| Id | PRD requirement | Checkpoint | Status | Evidence |
|---|---|---|---|---|
| D-1 | Versioned, queryable exploit store | P2 model, P7 store | partial | P2 model complete: [schema.sql](../src/agentforge/store/schema.sql), indexes, `schema_migrations`. No agent writes it. P7 store not started |
| D-2 | Full suite runs when the Orchestrator triggers it | P7 | not started | |
| D-3 | Detect a fixed vulnerability reappearing, and a fix in one category regressing another | P7 | not started | |
| D-4 | A passing regression means fixed, not drifted: repeat runs, assert on side effects | P7 | not started | |
| D-5 | Answers to all six observability questions, queryable, and readable by the Orchestrator | P8 | not started | ADR-006 chooses SQLite traces. No trace store exists |
| D-6 | Data model for exploits, regression cases, run logs, coverage metrics | P2 | met | [schema.sql](../src/agentforge/store/schema.sql): all four tables. Closure audit 2026-10-17 |
| D-7 | Data quality: unique id, required fields, no duplicate attack sequence | P2 constraints, P7 enforcement | partial | P2 constraints met: unique id, required fields, unique `sequence_hash`. `tests/test_store.py` raises `DuplicateSequence` and `IncompleteRecord`. Documentation-agent enforcement is P7 |
| D-8 | Access control: who writes exploits, who reads, what approval precedes publication | P2 design, P9 enforcement | partial | P2 design met: [ACCESS_CONTROL.md](ACCESS_CONTROL.md). Insert refuses `published` (`test_published_insert_is_rejected`). Role-scoped enforcement is P9 |
| D-9 | Migration of existing records without data loss, with a migration note per schema change | P2 | met | [migrate.py](../src/agentforge/store/migrate.py) refuses a missing note. Manual check: original row unchanged, new column populated. Note: [0001-initial-schema.md](migrations/0001-initial-schema.md) |
| D-10 | SQL indexes on severity, category and system version, and a regression SLO verified in CI | P8 | not started | Applies, because ADR-005 chose SQLite. Q7 |
| D-11 | Queue depth and backup behavior | P6, only if a queue is used | not started | ADR-003 rejected a queue. The requirement does not apply unless that decision changes. Q7 |
| D-12 | Baseline CPU, memory, latency and throughput for 100 cases plus the full regression suite | P8 | not started | |
| D-13 | Load test of 100 consecutive cases against the live target, bottleneck named, fix documented | P8 | not started | Needs human approval and the cost cap |

## Contracts and interfaces

| Id | PRD requirement | Checkpoint | Status | Evidence |
|---|---|---|---|---|
| C-1 | Versioned schemas (minimum v1) for Orchestrator to Red Team, Red Team to Judge, Judge to Documentation, Judge to harness | P2 | met | `contracts/v1/campaign_request.schema.json`, `attack_result.schema.json`, `confirmed_exploit.schema.json`, `verdict.schema.json`. Each `schema_version` is `v1` |
| C-2 | Schemas published in `/contracts`. JSON Schema or equivalent | P2 | met | `contracts/v1/`, Draft 2020-12, including `defs.schema.json` and `errors/` |
| C-3 | Producer-side and consumer-side contract tests. A breaking change fails without a version bump | P2 | met | `tests/test_contracts.py`, `tests/test_contracts_nested.py` (16 passed), `tests/test_schema_diff.py`. Manual schema-diff check exited 1. CI step in `.github/workflows/ci.yml` |
| C-4 | Typed error schemas: target unreachable, budget exceeded, judge timeout, no findings in window, regression detected | P2 | met | Five schemas in `contracts/v1/errors/`. `test_each_error_validates_against_its_own_schema`, `test_unknown_error_code_is_rejected` |
| C-5 | A migration note for every interface change | P2 | met | [DECISIONS.md](DECISIONS.md) section 5, both rows. Note: [0001-initial-schema.md](migrations/0001-initial-schema.md). `test_a_migration_without_a_note_is_refused` |
| C-6 | Rate limits and auth documented for every external API, with backoff, queue or abort | P5 | not started | Target limiter is described in the threat model. Platform behavior is not documented as a spec yet |
| C-7 | Pagination documented | P5 | unconfirmed | None of the planned APIs are paged. Confirm at P5 and mark not applicable if it stays that way, rather than inventing pages |

## Security, safety, cost

| Id | PRD requirement | Checkpoint | Status | Evidence |
|---|---|---|---|---|
| E-1 | Target allowlist, default deny, one HTTP chokepoint, off-list redirect refused | P0 skeleton, complete before P3 | partial | Chokepoint, refusal log and rate cap exist. `config/allowlist.yaml` is still empty. No live transport. G-4 resolved by `tests/test_p3_envelope.py`; row kept |
| E-2 | Adding an allowlist entry is a reviewed change, never automatic | P0 | partial | `.github/CODEOWNERS` lists `config/`. Review is not enforced until branch protection is on. G-5 |
| E-3 | Target identity check before each run | P3 | partial | `src/agentforge/safety/identity.py` checks a stub login body for `OpenEMR` and rejects a redirect. The session client can issue that GET through the chokepoint, but only a fake transport has been used. The read-only GET of the public login page was not made. Reachability stays UNVERIFIED |
| E-4 | Per-run and per-day USD caps, attack-count cap, approval token bound to the exact caps | P0 | partial | `src/agentforge/safety/budget.py` and tests. No run is approved |
| E-5 | Kill switch halts before the next call | P0 | met | `budget.py`. Tested, and confirmed by a user-run smoke test recorded in [PROGRESS.md](PROGRESS.md) |
| E-6 | Provider-side spending limit on every key | Before the first live run | gap | The gate refuses while `config/spend_limits.yaml` is empty. The limits are not set. Q13. Cannot be verified from the repo |
| E-7 | Spend metered per agent, including target-side spend | P4 | not started | |
| E-8 | Request-rate cap toward the target | P3 | met | `src/agentforge/safety/rate.py`. `test_rate_cap_stops_before_the_next_call`. A 429 is returned and not retried |
| E-9 | Synthetic data only. Transcripts that quote the target are scanned before storage | P3 | met | `src/agentforge/safety/phi.py`. `evals/fixtures/synthetic-intake.txt`. `test_phi_blocks_store`. A-001 is still unverified for the running deployment; that does not reopen this row |
| E-10 | CI makes no live or paid call. Secrets never reach a forked PR | P0 | met | `.github/workflows/ci.yml` has no secrets. `scripts/check_workflows.py` forbids `pull_request_target` and secret references |
| E-11 | OWASP Web Top 10 and LLM Top 10 mapped, non-applicable items explained, SSRF checked against the code | P1 mapping, P3 per case | met | P1 half unchanged. P3 half: each of the six cases names an OWASP id already in [THREAT_MODEL.md](../THREAT_MODEL.md) (`LLM01`, `A01`, `A07`, `LLM04`). The suite does not claim every OWASP row has a case. SSRF remains a code reading, not a proof |
| E-12 | Every case exercises a boundary, an invariant or a regression risk. Static payload lists do not count | P3 | met | `evals/schema/case.schema.json` requires `exercise`. The six cases use `invariant`, `boundary` and `regression_risk`. `scripts/check_evals.py` exits 0 |
| E-13 | Auth model: which agent calls which target with which credential. Role-scoped database access | P9 | not started | |
| E-14 | Harmful generated content: storage and redaction rules | P9 | not started | |
| E-15 | Audit trail sufficient to reconstruct an overnight run | P9 | not started | |
| E-16 | Platform self-scan: coverage floor, type check, dependency audit, Bandit | P9 | partial | Coverage, mypy and Bandit already run in CI, ahead of the roadmap ladder. pip-audit and the self-scan do not |

## Required exercises and submission artifacts

| Id | PRD requirement | Checkpoint | Status | Evidence |
|---|---|---|---|---|
| X-1 | Triage lab: at least ten findings across critical, high, medium and false positive, each with a disposition | P10 | not started | |
| X-2 | ATO-style evidence packet, separate from the architecture doc | P10 | not started | Treated as distinct from the Defense packet (Q6, unconfirmed) |
| X-3 | Integration with a peer's agent through the published contract only, no shared source | P10 | unconfirmed | Depends on a peer existing. Q4. If none, the packet is labeled stub conformance (D-008) and is not called peer integration |
| X-4 | Lab: build one component, inherit another | P10 | unconfirmed | Same dependency as X-3 |
| X-5 | Failure drills: target unreachable, budget exceeded, judge timeout, each yielding its typed error | P10 | not started | Error schemas are C-4 |
| X-6 | AI cost analysis: actual spend, and projections at 100, 1K, 10K and 100K from measured per-run cost | P10 | not started | Spend log in [PROGRESS.md](PROGRESS.md) is empty. Actual-spend-at-MVP is the plan (Q5) |
| X-7 | Demo video, 3 to 5 minutes, live attacks, one per submission | P11 | unconfirmed | Final is required. Whether MVP needs its own is Q5 |
| X-8 | Social post tagging @GauntletAI | P11 | not started | PRD says final only |
| X-9 | AI-use disclosure in `ARCHITECTURE.md`: every AI role, the check or approval after each AI decision, remaining risk | P5 | not started | |

## How to update this file

A checkpoint is not `met` here until [PROGRESS.md](PROGRESS.md) has the evidence. When a row moves, change its status
and name the file or the command. Do not mark a row met because the roadmap says the checkpoint is done.
