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
| G-3 | P0 | Evidence packet message schemas are names, not JSON Schemas | Not a gap. The roadmap assigns the schema list to P0 and the schemas to P2 |
| G-4 | P0 | Off-list refusals are raised, not logged. ROADMAP 2.2 says refused and logged | Not a P0 miss. Logging is part of the envelope that must exist before the first live run, so it is P3. No logging code added |
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

## Hard gates

| Id | PRD requirement | Checkpoint | Status | Evidence |
|---|---|---|---|---|
| H-1 | Deployed target URL submitted with every checkpoint | P0, then every checkpoint | gap | No URL in [TARGET_FREEZE.md](TARGET_FREEZE.md). Q2 open. G-1 |
| H-2 | `THREAT_MODEL.md` with a ~500-word summary first, six categories, four attributes each | P1 | met | [THREAT_MODEL.md](../THREAT_MODEL.md). Summary 543 words. `scripts/check_threat_model.py`: 0 problems. Closure audit 2026-10-17 |
| H-3 | `evals/` with results from at least three attack categories | P3 | not started | No `evals/` directory |
| H-4 | One agent role running live against the deployed target | P4 | not started | No agent code. `LIVE_ENABLED` is false |
| H-5 | `ARCHITECTURE.md` with a ~500-word summary, each agent named, a diagram | P5 | not started | Draft diagram only, in [DEFENSE_PACKET.md](DEFENSE_PACKET.md) |

## Stage deliverables

| Id | PRD requirement | Checkpoint | Status | Evidence |
|---|---|---|---|---|
| S-1 | Target stood up, changes to reach a testable state documented | P0 | partial | Pin, tree equality and "no changes by this repo" in [TARGET_FREEZE.md](TARGET_FREEZE.md). The running stack is not confirmed equal to the pin |
| S-2 | Attack surface map, including the five target-specific surfaces | P1 | met | [THREAT_MODEL.md](../THREAT_MODEL.md), surfaces table and `TM-PI` to `TM-ID` |
| S-3 | Platform-side threats (a target response or a transcript steering the Judge or Documentation agent) | P1 | met | `TM-PL-1`, `TM-PL-2` |
| S-4 | `USERS.md`: users, workflows, use cases, why automation | P1 | met | [USERS.md](../USERS.md). Due checkpoint unconfirmed (Q5); written at P1 anyway |
| S-5 | Build-versus-configure record before any agent: Burp, ZAP, Semgrep, Garak, commercial platforms, and why custom code is or is not justified | P0 | partial | [BUILD_VS_CONFIGURE.md](BUILD_VS_CONFIGURE.md) covers each named tool plus promptfoo, PyRIT and deterministic tooling. Claims are unverified. G-2 |
| S-6 | Architecture Defense evidence packet: diagram, message schemas, trust boundaries, failure modes | P0 | met as a draft | [DEFENSE_PACKET.md](DEFENSE_PACKET.md). Schemas are names; JSON Schemas are P2 (G-3) |
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
| D-1 | Versioned, queryable exploit store | P2 model, P7 store | not started | SQLite is the decision (ADR-005), not the schema |
| D-2 | Full suite runs when the Orchestrator triggers it | P7 | not started | |
| D-3 | Detect a fixed vulnerability reappearing, and a fix in one category regressing another | P7 | not started | |
| D-4 | A passing regression means fixed, not drifted: repeat runs, assert on side effects | P7 | not started | |
| D-5 | Answers to all six observability questions, queryable, and readable by the Orchestrator | P8 | not started | ADR-006 chooses SQLite traces. No trace store exists |
| D-6 | Data model for exploits, regression cases, run logs, coverage metrics | P2 | not started | |
| D-7 | Data quality: unique id, required fields, no duplicate attack sequence | P2 constraints, P7 enforcement | not started | |
| D-8 | Access control: who writes exploits, who reads, what approval precedes publication | P2 design, P9 enforcement | not started | |
| D-9 | Migration of existing records without data loss, with a migration note per schema change | P2 | not started | |
| D-10 | SQL indexes on severity, category and system version, and a regression SLO verified in CI | P8 | not started | Applies, because ADR-005 chose SQLite. Q7 |
| D-11 | Queue depth and backup behavior | P6, only if a queue is used | not started | ADR-003 rejected a queue. The requirement does not apply unless that decision changes. Q7 |
| D-12 | Baseline CPU, memory, latency and throughput for 100 cases plus the full regression suite | P8 | not started | |
| D-13 | Load test of 100 consecutive cases against the live target, bottleneck named, fix documented | P8 | not started | Needs human approval and the cost cap |

## Contracts and interfaces

| Id | PRD requirement | Checkpoint | Status | Evidence |
|---|---|---|---|---|
| C-1 | Versioned schemas (minimum v1) for Orchestrator to Red Team, Red Team to Judge, Judge to Documentation, Judge to harness | P2 | not started | Names only, in [DEFENSE_PACKET.md](DEFENSE_PACKET.md) |
| C-2 | Schemas published in `/contracts`. JSON Schema or equivalent | P2 | not started | |
| C-3 | Producer-side and consumer-side contract tests. A breaking change fails without a version bump | P2 | not started | |
| C-4 | Typed error schemas: target unreachable, budget exceeded, judge timeout, no findings in window, regression detected | P2 | not started | Names only |
| C-5 | A migration note for every interface change | P2 | not started | The log exists and is empty: [DECISIONS.md](DECISIONS.md) section 5 |
| C-6 | Rate limits and auth documented for every external API, with backoff, queue or abort | P5 | not started | Target limiter is described in the threat model. Platform behavior is not documented as a spec yet |
| C-7 | Pagination documented | P5 | unconfirmed | None of the planned APIs are paged. Confirm at P5 and mark not applicable if it stays that way, rather than inventing pages |

## Security, safety, cost

| Id | PRD requirement | Checkpoint | Status | Evidence |
|---|---|---|---|---|
| E-1 | Target allowlist, default deny, one HTTP chokepoint, off-list redirect refused | P0 skeleton, complete before P3 | partial | `src/agentforge/safety/allowlist.py`, `chokepoint.py`, tests. Empty allowlist. No live transport. Redirect logging is G-4 |
| E-2 | Adding an allowlist entry is a reviewed change, never automatic | P0 | partial | `.github/CODEOWNERS` lists `config/`. Review is not enforced until branch protection is on. G-5 |
| E-3 | Target identity check before each run | P3 | not started | |
| E-4 | Per-run and per-day USD caps, attack-count cap, approval token bound to the exact caps | P0 | partial | `src/agentforge/safety/budget.py` and tests. No run is approved |
| E-5 | Kill switch halts before the next call | P0 | met | `budget.py`. Tested, and confirmed by a user-run smoke test recorded in [PROGRESS.md](PROGRESS.md) |
| E-6 | Provider-side spending limit on every key | Before the first live run | gap | The gate refuses while `config/spend_limits.yaml` is empty. The limits are not set. Q13. Cannot be verified from the repo |
| E-7 | Spend metered per agent, including target-side spend | P4 | not started | |
| E-8 | Request-rate cap toward the target | P3 | not started | |
| E-9 | Synthetic data only. Transcripts that quote the target are scanned before storage | P3 | not started | A-001 is unverified for the running deployment |
| E-10 | CI makes no live or paid call. Secrets never reach a forked PR | P0 | met | `.github/workflows/ci.yml` has no secrets. `scripts/check_workflows.py` forbids `pull_request_target` and secret references |
| E-11 | OWASP Web Top 10 and LLM Top 10 mapped, non-applicable items explained, SSRF checked against the code | P1 mapping, P3 per case | partial | P1 half met: [THREAT_MODEL.md](../THREAT_MODEL.md), D-013. Names checked against the official 2021 Web and 2023 v1.1 LLM pages on 2026-10-17. No attacker-controlled outbound URL construction was identified at the pin. That is not proof SSRF is impossible. Per-case mapping is P3 |
| E-12 | Every case exercises a boundary, an invariant or a regression risk. Static payload lists do not count | P3 | not started | |
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
