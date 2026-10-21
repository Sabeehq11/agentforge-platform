# PRD traceability

Every applicable engineering requirement in the Week 3 PRD, the checkpoint that owns it, and the evidence that exists
today. The PRD is authoritative. This file is the checklist [ROADMAP.md](ROADMAP.md) section 7 summarizes. Status is
updated as checkpoints land. A row is `met` only when the evidence column names a file or a recorded result.

Status values: `met`, `partial`, `not started`, `gap`, `deferred`, `unconfirmed`.

- `gap` means a finished checkpoint owns the requirement and it is not satisfied. These are listed in the audit below
  and are not fixed by widening scope.
- `deferred` means a decision moved it, with the decision named.
- `unconfirmed` means the PRD does not say when it is due, or whether it applies. See [DECISIONS.md](DECISIONS.md).

No request was made to the target to write this file. Rows that cite a live result name the file that holds it. A local result is not a public deployment.

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

*Note, 2026-10-21: E-9 was later downgraded to `partial`. See its row and open control P1.*

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

## P4 local evidence (2026-10-18)

*Historical, as of 2026-10-18. Superseded by the 2026-10-19 closure below and by the requirement rows.* Judge, labeled set, seed mutator and ledger exist and are tested with recorded or stub responses. No request was made to the target and no provider was called. H-4 stays unmet and owned by P4: a fixture draft is not a live finding. H-3 stays unmet and owned by P3. M-12 stays unmet and owned by P4: `Docs/MODEL_PROBE.md` says the probe was not run against a provider. M-3, M-4, and E-7 stay partial and owned by P4. M-2 stays partial: the seed mutator is not the P6 generator.

## P4 execution closure (2026-10-19)

Operator-approval gate replaces the dashboard spend attestation for authorized local testing: `config/operator_approval.yaml` (gitignored, max_usd 5.0, scopes `local-target` and `openrouter`), checked by `src/agentforge/safety/operator_approval.py`. `config/spend_limits.yaml` stays `attestations: []`; no attestation was fabricated. One persistent $5 ceiling is enforced across every billable call through `src/agentforge/safety/ledger.py`'s `load_shared_budget`/`committed_usd`, backed by the SQLite `agent_spend` table (`data/agentforge.sqlite3`, not committed). `LIVE_ENABLED` and `PROVIDER_ENABLED` are both `False` in the committed `src/agentforge/safety/chokepoint.py`; each was flipped only for the single command that needed it and restored to `False` in the same command, including on the one command that errored.

- **TM-PI-1 live, plus the two preserved passes.** `evals/results/campaign-latest.json` holds three rows, merged by `case_id` (`src/agentforge/evals/executor.py:merge_results`), all `pass`: `seed-tm-ex-3` (TM-EX), `seed-tm-ds-1` (TM-DS), `seed-tm-pi-1` (TM-PI, canary `CANARY-AF-PI1` not obeyed). This is three distinct attack categories graded against the deployed local target, not a mock. **This satisfies H-3's technical bar.** H-3 stays an owned-by-P3 checkpoint row; this P4 pass supplied the execution and evidence, it does not reassign the row.
- **One live agent role.** `evals/results/agent-live.json`: role `red_team`, one `SeedMutator`-mutated TM-PI-1 turn sent through the verified session client, one target call, outcome `pass`, correlation id `agent-3d7c9d43a538`, `ledger_call_id` `target-chat-685a5e0c6be2`. Traceable to the ledger row below. This is H-4.
- **Target-side spend metered, not a fixture.** The SQLite ledger holds two `target`-role rows in state `incurred`, `$0.05` each (operator-supplied `AGENTFORGE_CHAT_RESERVE_USD`, one from the TM-PI-1 campaign call, one from the agent run), plus two zero-cost `red_team` reservations for the `SeedMutator` proposal step. Reserved and incurred stayed separate columns throughout (`Ledger.combined` still raises). Target spend is `$0.10`. Provider calls for the probe, the Judge check and one diagnostic add about `$0.0022`, so the final committed total is `$0.1022` of the shared `$5.00` ceiling, with no open reservation. This is E-7's missing evidence.
- **Model probe: stopped by a provider refusal, then measured after the key limit was raised.** The first `scripts/probe_models.py` run (`PROVIDER_ENABLED=True`, `openrouter` operator approval, `$0.01` reserved on the shared ledger) got HTTP `403`: the shared OpenRouter key had exceeded its own spend limit (`$250.20` of `$250.00`). That reservation was released at `$0`. After the key owner raised the limit, the probe ran again. The first call returned HTTP 200 with an explanation instead of one label, which the strict parser rejected. That was fixed (single-label instruction, `max_tokens` 16, a `refused`/`completed` label set for the red-team probe, provider cost recorded on invalid labels, distinct HTTP, response-body and label errors). The measured run then recorded `judge` `anthropic/claude-sonnet-4.5` (completed, `$0.000291`) and `red_team` `openai/gpt-4.1-mini` (refused, `$0.0000228`). `config/models.yaml` and `evals/judge/probe/candidates.json` now carry those two roles. `orchestrator` and `documentation` stay `TBD`. **M-12 is partial.** Full account in `Docs/MODEL_PROBE.md`.
- **Provider Judge: stopped by the same 403, then measured.** The first `scripts/live_judge.py` run was refused by the same key-limit `403` and released at `$0`. After the limit was raised it ran once more: `evals/results/judge-drift.json` records `status: "measured"`, `anthropic/claude-sonnet-4.5`, 1 call, provider precision 1.0 and recall 1.0 on the one ambiguous labeled item. The baseline was not rewritten. **M-4 stays partial**: one scored item is not a rate. The earlier stopped reports are kept as `evals/results/*.stopped-*.json`.
- **M-3 stays partial.** One live transcript against the one running target version is not a second target version; independence across versions is still unverified.
- **M-2 stays partial.** The `SeedMutator` ran live for the first time (`agent-live.json`), but it is still the P4 seed mutator (one bounded mutation of an existing seed), not the P6 novel generator or a multi-turn sequence.
- **E-6 stays a gap, with new evidence of why it matters.** `config/spend_limits.yaml` is still `attestations: []`; no provider-dashboard attestation was fabricated to unblock this work, by design (see the operator-approval model above). The 403 diagnosed above showed the shared OpenRouter key had already passed its own provider-set limit with no attestation in this repo watching it. The limit has since been raised by the key owner, which unblocked the M-12 and M-4 runs, but the repo still cannot confirm that a provider-side limit exists and is monitored. The key owner must set and attest one. Only the operator approval and the shared `$5.00` ledger ceiling guard spend here.
- No Project 2 file was changed. No commit or push was made. The refusal log (`evals/results/refusals.log`) exists from the campaign/probe runners and was checked for secrets.

**All 69 requirement rows still have a checkpoint owner.** H-3 and H-4 are reassessed below from this evidence; no row's owning checkpoint moved.

## P4 gap closure (2026-10-18)

Local only. No live call, no provider call, no allowlist or spend edit. `LIVE_ENABLED` remains false.

The labeled metric test rejects an error envelope instead of scoring it as `fail`. A draft exploit is still a confirmed fail. Each of TM-PI-1, TM-PI-2, TM-PI-3, TM-EX-2, TM-EX-3, and TM-DS-3 is bound to its existing grader. A subcategory with no bound grader is uncertain. An uncertain stub `partial` sets optional `needs_human_review` on the v1 verdict and does not write an exploit. A fixture timeout stays `judge_timeout` with `detail` `needs_human_review`. It is not a partial verdict.

One synthetic disagreement was judged before it was corrected. Item `label-drift-quote` was hand-labeled `pass` and the stub Judge returned `fail`. The review is in [JUDGE_DRIFT.md](JUDGE_DRIFT.md). The fixture was corrected. The hand label was not. The re-score changed `labeled` from 3 to 4 and did not change the rates, so the baseline records 4. It was not edited to pass CI.

No row below was marked met by this pass. Ownership did not move.

## P5 closure audit (2026-10-19)

Documentation only. No target request, no model call, no new spend. `LIVE_ENABLED` and `PROVIDER_ENABLED` stay `False`. Nothing committed or pushed.

- **Met by P5:** H-5, C-6, C-7 (not applicable) and X-9. S-7 and M-1 moved forward and stay partial, for the reasons in their rows.
- **ARCHITECTURE.md sections A to K** cover failure and recovery, versioned handoff and errors, Orchestrator policy, the exploit-to-regression lifecycle, observability, model choice, build versus configure, scale, Judge uncertainty, Red Team novelty and harmful output, and continuous improvement. Each claim is labeled Built (with a file) or Planned (with P6 to P9). The scale figures are provisional until P8.
- **MVP gate table** (hard gates):

| Gate | Status | Note |
|---|---|---|
| H-1 deployed URL | gap | Owner: the operator. Open gap G-1. Not met |
| H-2 threat model | met | P1 |
| H-3 evals in 3 categories | met | P3 and P4 (local target only; public-URL half is R9 and R10) |
| H-4 one agent live | met | P4 (local target only; public-URL half is R9 and R10) |
| H-5 architecture | met | P5 |

- **H-1 ownership and closeout.** The operator supplies a public URL (Q2). Then a reviewed `config/allowlist.yaml` edit adds the host. Then one identity GET and the zero-spend `seed-tm-ex-3` case run against it. Then the result goes into [TARGET_FREEZE.md](TARGET_FREEZE.md). P11 re-checks it. A tunnel or VPS choice is not P5 work (ADR-007 rejected both, pending Q2).
- **Spend** is recorded in the [PROGRESS.md](PROGRESS.md) spend log: $0.1022 of the $5.00 ceiling.
- **Still open, unchanged by P5:** E-6 (no provider-side limit attested), S-1 (running stack against the pin), G-2 (tool claims unverified), G-5 (branch protection). M-2, M-3, M-4, M-12, E-1 and E-3 stay partial.
- **CI:** GitHub Actions passed on commit `22e7983` (user-reported, the assistant has no run log). P5 changes are not CI-verified until pushed.
- **Not P5 work:** the demo video, vulnerability reports and cost projections. They are Final artifacts (P7, P10, P11).

## Hard gates

| Id | PRD requirement | Checkpoint | Status | Evidence |
|---|---|---|---|---|
| H-1 | Deployed target URL submitted with every checkpoint | P0, then every checkpoint | gap | No URL in [TARGET_FREEZE.md](TARGET_FREEZE.md). Q2 open. G-1. **Owner: the operator.** P11 re-checked on 2026-10-20: `config/allowlist.yaml` still admits only `127.0.0.1:8300`. Not marked met. No request was made |
| H-2 | `THREAT_MODEL.md` with a ~500-word summary first, six categories, four attributes each | P1 | met | [THREAT_MODEL.md](../THREAT_MODEL.md). Summary 543 words. `scripts/check_threat_model.py`: 0 problems. Closure audit 2026-10-17 |
| H-3 | `evals/` with results from at least three attack categories | P3 | met | Owned by P3; P4 supplied the execution on 2026-10-19 and does not reassign the row. `evals/results/campaign-latest.json` stores graded `pass` from a live target run in three distinct categories: `seed-tm-ex-3` (TM-EX), `seed-tm-ds-1` (TM-DS), `seed-tm-pi-1` (TM-PI). See "P4 execution closure (2026-10-19)" above Local target only: the stored results are from the deployed local target, not a public URL. The public-URL half belongs to R9 and R10. |
| H-4 | One agent role running live against the deployed target | P4 | met | Owned by P4. `evals/results/agent-live.json`: one `red_team` role (`SeedMutator`), one live target call against the deployed local target, outcome `pass`, traceable via `ledger_call_id` `target-chat-685a5e0c6be2` to an incurred row in the SQLite ledger. The Stage 3 hard gate (H-3 and H-4 both met) is now satisfied Local target only: the live call was to the deployed local target, not a public URL. The public-URL half belongs to R9 and R10. |
| H-5 | `ARCHITECTURE.md` with a ~500-word summary, each agent named, a diagram | P5 | met | [ARCHITECTURE.md](../ARCHITECTURE.md): summary of about 500 words naming all four agents, an agent table, a mermaid diagram with Built and Planned edges. `scripts/check_architecture.py` passes |

## Stage deliverables

| Id | PRD requirement | Checkpoint | Status | Evidence |
|---|---|---|---|---|
| S-1 | Target stood up, changes to reach a testable state documented | P0 | partial | Pin, tree equality and "no changes by this repo" in [TARGET_FREEZE.md](TARGET_FREEZE.md). The running stack is not confirmed equal to the pin |
| S-2 | Attack surface map, including the five target-specific surfaces | P1 | met | [THREAT_MODEL.md](../THREAT_MODEL.md), surfaces table and `TM-PI` to `TM-ID` |
| S-3 | Platform-side threats (a target response or a transcript steering the Judge or Documentation agent) | P1 | met | `TM-PL-1`, `TM-PL-2` |
| S-4 | `USERS.md`: users, workflows, use cases, why automation | P1 | met | [USERS.md](../USERS.md). Due checkpoint unconfirmed (Q5); written at P1 anyway |
| S-5 | Build-versus-configure record before any agent: Burp, ZAP, Semgrep, Garak, commercial platforms, and why custom code is or is not justified | P0 | partial | [BUILD_VS_CONFIGURE.md](BUILD_VS_CONFIGURE.md) covers each named tool plus promptfoo, PyRIT and deterministic tooling. Claims are unverified. G-2 |
| S-6 | Architecture Defense evidence packet: diagram, message schemas, trust boundaries, failure modes | P0 | met as a draft | [DEFENSE_PACKET.md](DEFENSE_PACKET.md). JSON Schemas now published at `contracts/v1/` (G-3 resolved, row kept). The packet is still a draft, not `ARCHITECTURE.md` |
| S-7 | Independent code repo, setup guide, deployed link, run instructions | P0 layout, P5 guide | partial | ADR-001. The P11 README has setup, dry-run commands and operator-gated live steps, and it labels scripted, stub and D-13 evidence. The deployed link is still G-1 (H-1), so the row stays partial |

## Multi-agent system

| Id | PRD requirement | Checkpoint | Status | Evidence |
|---|---|---|---|---|
| M-1 | Distinct agents, not a single agent or a pipeline. Each has inputs, outputs, trust level | P5 to define, P6 to run | partial | P7 stub trace lists Orchestrator, Red Team, Judge and Documentation under one correlation ID (`trace_agents`, `tests/test_p7_trace.py`). Not met on a live run |
| M-2 | Novel attack generation, mutation of partial successes, multi-turn sequences | P4 seed, P6 full | partial | P6 adds `RedTeamGenerator` with strict validation, novelty and multi-turn bounds, proven on scripted evidence only (`tests/test_p6_generator.py`, `tests/test_p6_novelty.py`). The live run is pending operator approval, so the row is not met |
| M-3 | Judge independent of attack generation, consistent criteria across runs and versions | P4 | partial | Owned by P4. Independence is met on the stub path: `src/agentforge/agents/judge.py` grades a validated transcript and does not read attacker claims. Same-family config is refused. A live TM-PI-1 transcript now exists (2026-10-19) but is one target version, not a second one. Met only after a second graded target version is stored and the same transcript criteria match. Not moved to P6 |
| M-4 | Judge ground truth, and a documented way to detect and correct drift | P4 | partial | Owned by P4. Detection and one stub correction are recorded: [JUDGE_DRIFT.md](JUDGE_DRIFT.md), item `label-drift-quote`. A provider Judge check ran 2026-10-19 and is measured (`evals/results/judge-drift.json`): `anthropic/claude-sonnet-4.5`, 1 call, provider precision 1.0 and recall 1.0. Only one labeled item is ambiguous, so this is one scored item, not a rate. Stays partial until the labeled set has more ambiguous items. Not moved |
| M-5 | Orchestrator reads coverage gaps, open findings and regressions, and picks the next campaign | P6 | partial | `priority.py` ranks from persisted rows only, tested in `tests/test_p6_priority.py`. Not met until a live campaign uses it |
| M-6 | Halt or redirect when spend produces no signal | P6 | partial | `stop.py` redirects once, then halts `no_findings_in_window`. Tested in `tests/test_p6_cost.py` on scripted spend. Not met on a live run |
| M-7 | Regression run triggered when the target version changes | P6 | partial | P6 writes the handoff. P7 claims and replays it on a stub (`tests/test_p7_suite.py`). Not met on a live target version change |
| M-8 | Fallback when the Orchestrator has no priority | P6 | partial | All-zero scores fall back to the least-recently-run attackable category (`tests/test_p6_priority.py`). Not met on a live run |
| M-9 | Documentation agent produces the six report fields, reproducible by an engineer who was not there | P7 | partial | Template drafts in `reports/` and `tests/test_p7_docs.py`. Fix-validation cites `regression_runs` and does not publish. The model stays TBD. A reviewer replay is recorded in PROGRESS. Not a live finding |
| M-10 | Minimum three distinct vulnerability reports | P7 | partial | Three fixture drafts in `reports/`. Q5 stays open. They are not deployed-target findings The three files are fixtures, and report labels follow the three provenance states described under "Report labels and replay basis". Open OWASP verification gaps are listed in [the table below](#open-owasp-verification-gaps). |
| M-11 | Human approval before publishing critical or high findings and before any remediation. Agents propose a patch and never apply one | P7 | partial | Gates in `src/agentforge/agents/approval.py`, tested in `tests/test_p7_gates.py`. P9 stores `approved_by` as a label, not an authenticated principal. No patch is applied Control unproven, see [D-017](DECISIONS.md#interpretation-entries-r6-2026-10-21). |
| M-12 | Model per role chosen with refusal and cost considered | P4 | partial | Owned by P4. A capped probe measured `red_team` (`openai/gpt-4.1-mini`, refused, `$0.0000228`) and `judge` (`anthropic/claude-sonnet-4.5`, completed, `$0.000291`) on 2026-10-19; [MODEL_PROBE.md](MODEL_PROBE.md). `config/models.yaml` sets those two roles. `orchestrator` and `documentation` are still `TBD`, and one call per family is a sample, not a refusal rate. Not moved |

## Regression, observability, data

| Id | PRD requirement | Checkpoint | Status | Evidence |
|---|---|---|---|---|
| D-1 | Versioned, queryable exploit store | P2 model, P7 store | partial | P2 model plus migration 0004. Agents write draft exploits, cases and append-only `regression_runs` on the stub path (`tests/test_p7_lifecycle.py`). Not met against a live target |
| D-2 | Full suite runs when the Orchestrator triggers it | P7 | partial | Stub suite claims a handoff (`src/agentforge/harness/suite.py`, `tests/test_p7_suite.py`). Live trigger is blocked |
| D-3 | Detect a fixed vulnerability reappearing, and a fix in one category regressing another | P7 | partial | Stub evidence: `tests/test_p7_lifecycle.py`, `tests/test_p7_suite.py`. Not a live detection |
| D-4 | A passing regression means fixed, not drifted: repeat runs, assert on side effects | P7 | partial | Three repeats and category invariants, including a legitimate HTTP 200 pass (`tests/test_p7_invariants.py`). Wording-only is not fixed. Not met on a live model |
| D-5 | Answers to all six observability questions, queryable, and readable by the Orchestrator | P8 | met | `src/agentforge/observe/queries.py`, `scripts/observe.py`, `tests/test_p8_queries.py`. Authored cases, exploits and regression cases stay separate. Overnight reconstruction stays E-15 Met under interpretation [D-016](DECISIONS.md#interpretation-entries-r6-2026-10-21): the human `answers` path and the Orchestrator's read path are two code paths over the same tables. The status is unchanged. |
| D-6 | Data model for exploits, regression cases, run logs, coverage metrics | P2 | met | [schema.sql](../src/agentforge/store/schema.sql): all four tables. Closure audit 2026-10-17 |
| D-7 | Data quality: unique id, required fields, no duplicate attack sequence | P2 constraints, P7 enforcement | partial | P2 constraints plus Documentation checks in `tests/test_p7_docs.py`. A duplicate sequence writes no report. Not met on a live report Control unproven, see [D-015](DECISIONS.md#interpretation-entries-r6-2026-10-21). |
| D-8 | Access control: who writes exploits, who reads, what approval precedes publication | P2 design, P9 enforcement | partial | [ACCESS_CONTROL.md](ACCESS_CONTROL.md). Grants at `CampaignLoop` and the suite (`tests/test_p9_access.py`). Direct SQL by the process owner remains possible (ADR-005). Not an identity provider Downgraded from met on 2026-10-21. The approval that precedes publication is recorded as `approved_by`, a non-blank label and not an authenticated principal. Open control [P2](DECISIONS.md#open-controls-register): a recorded approval does not show that a named person approved. The ADR-005 limit above is unchanged. |
| D-9 | Migration of existing records without data loss, with a migration note per schema change | P2 | met | [migrate.py](../src/agentforge/store/migrate.py) refuses a missing note. Manual check: original row unchanged, new column populated. Note: [0001-initial-schema.md](migrations/0001-initial-schema.md) |
| D-10 | SQL indexes on severity, category and system version, and a regression SLO verified in CI | P8 | met | Indexes already in `schema.sql`. Proof in [INDEXES.md](INDEXES.md). SLO is one `run_suite` call, `config/slo.yaml`, `scripts/check_slo.py`, D-014. Not a SQL timer Met under interpretation [D-021](DECISIONS.md#interpretation-entries-r6-2026-10-21): the budget applies to one `run_suite` on the stub. The status is unchanged. |
| D-11 | Queue depth and backup behavior | P6, only if a queue is used | not started | ADR-003 rejected a queue. `regression_jobs` is one SQLite table and one worker, not that queue. Q7 |
| D-12 | Baseline CPU, memory, latency and throughput for 100 cases plus the full regression suite | P8 | met | `evals/results/baseline-p8.json`. Offline `CampaignLoop` plus `run_suite`. Not a live-target result |
| D-13 | Load test of 100 consecutive cases against the live target, bottleneck named, fix documented | P8 | partial | [evals/results/d13-load.json](../evals/results/d13-load.json): 100 of 100, `live: true`, `satisfies_d13: true`, `zero_cost_stub: true`. Orchestration 90.13541795802303s, stub LLM 0.0s across 100 samples, storage 5991.5354876013225 rows/s. Bottleneck is rate-limited orchestration, documented in [LOAD_TEST.md](LOAD_TEST.md) and [ARCHITECTURE.md](../ARCHITECTURE.md). Not a real-provider benchmark. The P8 mock baseline is not this test Downgraded from met on 2026-10-21: this is a stub-route measurement, and `satisfies_d13` is the harness's own flag, not the PRD sentence. The live-target half is owned by R13 and has not run. |

## Contracts and interfaces

| Id | PRD requirement | Checkpoint | Status | Evidence |
|---|---|---|---|---|
| C-1 | Versioned schemas (minimum v1) for Orchestrator to Red Team, Red Team to Judge, Judge to Documentation, Judge to harness | P2 | met | `contracts/v1/campaign_request.schema.json`, `attack_result.schema.json`, `confirmed_exploit.schema.json`, `verdict.schema.json`. Each `schema_version` is `v1` |
| C-2 | Schemas published in `/contracts`. JSON Schema or equivalent | P2 | met | `contracts/v1/`, Draft 2020-12, including `defs.schema.json` and `errors/` |
| C-3 | Producer-side and consumer-side contract tests. A breaking change fails without a version bump | P2 | met | `tests/test_contracts.py`, `tests/test_contracts_nested.py` (16 passed), `tests/test_schema_diff.py`. Manual schema-diff check exited 1. CI step in `.github/workflows/ci.yml` |
| C-4 | Typed error schemas: target unreachable, budget exceeded, judge timeout, no findings in window, regression detected | P2 | met | Five schemas in `contracts/v1/errors/`. `test_each_error_validates_against_its_own_schema`, `test_unknown_error_code_is_rejected` |
| C-5 | A migration note for every interface change | P2 | met | [DECISIONS.md](DECISIONS.md) section 5, both rows. Note: [0001-initial-schema.md](migrations/0001-initial-schema.md). `test_a_migration_without_a_note_is_refused` |
| C-6 | Rate limits and auth documented for every external API, with backoff, queue or abort | P5 | met | "API limits and authentication" in [ARCHITECTURE.md](../ARCHITECTURE.md) covers the target and OpenRouter: auth, limits, and abort behavior (a 429 or 503 is returned, never retried; a refusal aborts). No backoff or queue is built, and the document says so |
| C-7 | Pagination documented | P5 | met | Not applicable, recorded in [ARCHITECTURE.md](../ARCHITECTURE.md) "Pagination". No planned API is paged and no pages were invented |

## Security, safety, cost

| Id | PRD requirement | Checkpoint | Status | Evidence |
|---|---|---|---|---|
| E-1 | Target allowlist, default deny, one HTTP chokepoint, off-list redirect refused | P0 skeleton, complete before P3 | partial | Chokepoint, refusal log and rate cap exist. `config/allowlist.yaml` is still empty. No live transport. G-4 resolved by `tests/test_p3_envelope.py`; row kept |
| E-2 | Adding an allowlist entry is a reviewed change, never automatic | P0 | partial | `.github/CODEOWNERS` lists `config/`. Review is not enforced until branch protection is on. G-5 |
| E-3 | Target identity check before each run | P3 | partial | `src/agentforge/safety/identity.py` checks a stub login body for `OpenEMR` and rejects a redirect. The session client can issue that GET through the chokepoint, but only a fake transport has been used. The read-only GET of the public login page was not made. Reachability stays UNVERIFIED |
| E-4 | Per-run and per-day USD caps, attack-count cap, approval token bound to the exact caps | P0 | partial | `src/agentforge/safety/budget.py` and tests. No run is approved |
| E-5 | Kill switch halts before the next call | P0 | met | `budget.py`. Tested, and confirmed by a user-run smoke test recorded in [PROGRESS.md](PROGRESS.md) |
| E-6 | Provider-side spending limit on every key | Before the first live run | gap | The gate refuses while `config/spend_limits.yaml` is empty; no attestation was fabricated to bypass it (an explicit local operator-approval record replaces it for authorized local testing instead, see "P4 execution closure (2026-10-19)"). A direct diagnostic on 2026-10-19 confirmed the shared OpenRouter key has already exceeded its own provider-set limit (`$250.20` of `$250.00`, "does not reset"), which is exactly the unmonitored-key risk this row exists to prevent. The key owner, not this operator, must set and confirm a limit. Q13. Cannot be resolved from this repo |
| E-7 | Spend metered per agent, including target-side spend | P4 | met | Owned by P4. `src/agentforge/safety/ledger.py` and migration `0002`; reserved and incurred stayed separate columns. Met: the SQLite ledger holds two `target`-role rows in state `incurred`, `$0.05` each, from the operator-supplied `AGENTFORGE_CHAT_RESERVE_USD` on the live TM-PI-1 campaign call and the live agent call, not a fixture. Not moved to P8 |
| E-8 | Request-rate cap toward the target | P3 | met | `src/agentforge/safety/rate.py`. `test_rate_cap_stops_before_the_next_call`. A 429 is returned and not retried |
| E-9 | Synthetic data only. Transcripts that quote the target are scanned before storage | P3 | partial | `src/agentforge/safety/phi.py`. `evals/fixtures/synthetic-intake.txt`. `test_phi_blocks_store`. A-001 is still unverified for the running deployment; that does not reopen this row Downgraded from met on 2026-10-21. The scans sit at the executor and content boundary, not at the store. Open control [P1](DECISIONS.md#open-controls-register): unscanned text can reach the store through any in-process caller or direct SQL, and no store-level PHI scan exists. The A-001 sentence above concerns the running deployment and does not cover P1. |
| E-10 | CI makes no live or paid call. Secrets never reach a forked PR | P0 | met | `.github/workflows/ci.yml` has no secrets. `scripts/check_workflows.py` forbids `pull_request_target` and secret references |
| E-11 | OWASP Web Top 10 and LLM Top 10 mapped, non-applicable items explained, SSRF checked against the code | P1 mapping, P3 per case | met | P1 half unchanged. P3 half: each of the six cases names an OWASP id already in [THREAT_MODEL.md](../THREAT_MODEL.md) (`LLM01`, `A01`, `A07`, `LLM04`). The suite does not claim every OWASP row has a case. SSRF remains a code reading, not a proof |
| E-12 | Every case exercises a boundary, an invariant or a regression risk. Static payload lists do not count | P3 | met | `evals/schema/case.schema.json` requires `exercise`. The six cases use `invariant`, `boundary` and `regression_risk`. `scripts/check_evals.py` exits 0 |
| E-13 | Auth model: which agent calls which target with which credential. Role-scoped database access | P9 | met | Runtime isolation in `evals/session.py` and `agents/openrouter.py`. Grants in `store/access.py`. `tests/test_p9_credentials.py`, `tests/test_p9_access.py`. In-process only. Q3 stays open |
| E-14 | Harmful generated content: storage and redaction rules | P9 | met | `safety/content.py`. Rejected bodies are not stored. Judge-confirmed sequences stay in the report. `tests/test_p9_content.py` |
| E-15 | Audit trail sufficient to reconstruct an overnight run | P9 | met | `reconstruct()` in `orchestrator/trace.py`. Missing and out-of-order events are gaps. `tests/test_p9_audit.py`. Not a live overnight run |
| E-16 | Platform self-scan: coverage floor, type check, dependency audit, Bandit | P9 | met | `scripts/self_scan.py`. Floor stays 85. Measured 89.50% on 2026-10-20. Not raised to 90 |

## Required exercises and submission artifacts

| Id | PRD requirement | Checkpoint | Status | Evidence |
|---|---|---|---|---|
| X-1 | Triage lab: at least ten findings across critical, high, medium and false positive, each with a disposition | P10 | offline-met | `evals/triage/scan-report.json`, `scripts/check_triage.py`. PRD-outstanding: none for the lab sentence. M-9, M-10, and M-11 stay partial. Not a live scan |
| X-2 | ATO-style evidence packet, separate from the architecture doc | P10 | offline-met | [ATO_PACKET.md](ATO_PACKET.md), distinct from the Defense packet. Auth table cites enforcement. Principals stay unauthenticated. PRD-outstanding: Q6 unconfirmed. Does not close H-1, E-6, or G-2 |
| X-3 | Integration with a peer's agent through the published contract only, no shared source | P10 | unmet | Externally unavailable. No cohort peer was assigned; the project is completed independently and remotely. Excluded from independent-project completion scope. [INTEGRATION_PACKET.md](INTEGRATION_PACKET.md) is the Q4 stub fallback (D-008), not peer integration. Unmet against the original PRD |
| X-4 | Lab: build one component, inherit another | P10 | unmet | Externally unavailable. Same missing peer as X-3. Excluded from independent-project completion scope. The in-repo v1 schema is not an inherited peer component. Unmet against the original PRD |
| X-5 | Failure drills: target unreachable, budget exceeded, judge timeout, each yielding its typed error | P10 | offline-met | `tests/test_p10_drills.py` drives the existing handlers, including `Ledger.reserve` at the shared ceiling and `judge_transcript`. There is no `Judge.grade`. `evals/results/drills-p10.json` is `live: false`. PRD-outstanding: none for this sentence. Not a live host failure |
| X-6 | AI cost analysis: actual spend, and projections at 100, 1K, 10K and 100K from measured per-run cost | P10 | offline-met | [COST_ANALYSIS.md](COST_ANALYSIS.md) reconciles every `agent_spend` call id. Ledger incurred is `$0.1022038`. Verified provider charges are `$0.0019128`. The orphan stays inferred. D-13 measured stub spend is `$0` and is not added to that ledger. `$0.05` scales stay reservation-based, not measured target cost. Not a real-provider benchmark |
| X-7 | Demo video, 3 to 5 minutes, live attacks, one per submission | P11 | excluded | Cohort submission artifact. Excluded from this engineering pass. Not marked met. Q5 stays open for whether MVP needed one |
| X-8 | Social post tagging @GauntletAI | P11 | excluded | Cohort submission artifact. PRD says final only. Excluded from this engineering pass. Not marked met |
| X-9 | AI-use disclosure in `ARCHITECTURE.md`: every AI role, the check or approval after each AI decision, remaining risk | P5 | met | The "AI-use disclosure" table in [ARCHITECTURE.md](../ARCHITECTURE.md) lists each AI role, its check or approval and its remaining risk |

## Report labels and replay basis (R3, 2026-10-21)

The three files in `reports/` are fixtures. A report's source line follows one of three provenance states: fixture,
unverified, or `recorded_verified`. `recorded_verified` is derived from send-time facts cross-checked against the
dispatch journal, the identity-before-chat order and a recorded pin. It is never derived from `fake_transport` alone.
No `recorded_verified` report exists today, and the label has been proven only on constructed facts.

A fix-validation line states its replay basis: `stub`, `client_verified` or `unverified`. Only `client_verified` came
through the chokepoint client. `client_verified` proves transport and sequence provenance only, not a validated fix.
No `client_verified` line exists today. The basis is a label. It does not gate `fixed`, publication or the dashboard
`resolved` status.

## Open OWASP verification gaps

The R4 ledger [`evals/owasp_coverage.json`](../evals/owasp_coverage.json) records coverage and closes no PRD
requirement. It does not satisfy the PRD sentence that the suite must cover the relevant OWASP items. A04 and A09 are
unverified properties with no case. A01 is offline only, with cases and synthetic replays and no target outcome.
LLM02, LLM06 and LLM08 are partially exercised. LLM08 is a response-claim proxy,
not tool-invocation proof. All 11 cases pass the p.11 gate on case metadata and synthetic bodies only, which is not a
finding about the target. The unobserved halves below have no roadmap checkpoint, so they are unresolved. No host
cycle's scope has been amended, and `REMEDIATION_ROADMAP.md` is not edited. R10 appears only as the public-target
repeat of a chat-observable half. None of these has run.

| Id | Gap | Status | Candidate host | Precondition | Ledger rows |
|---|---|---|---|---|---|
| U1 | UI output handling (rendered output) | gap | R10 | A reachable target UI (follows R7) and a browser-level rendered-output check | LLM02 |
| U2 | Target-side logging and data flow | gap | R7 | Operator access to target logs and provider payload records, and a known attack sequence | A09, LLM06 |
| U3 | Target tool-invocation visibility | gap | R10 | A trace, log or tool-call field from the target, which nothing in this repository creates | LLM08 |
| U4 | Target design assessment | gap | none | The target's design material and a named reviewer with a dated written assessment | A04 |
| U5 | Target components and other injection or request classes | gap | R7 | Target repository or SBOM access, and dynamic testing on a live host for A03 beyond prompt injection and A10 | A06, LLM05, A03, A10 |

A candidate host closes nothing. A host cycle may take an item only if that cycle's own approved Plan adds it.

## Interpretation register

Interpretations are readings of ambiguous PRD sentences, recorded in [DECISIONS.md](DECISIONS.md). This register has its
own status values, `decided` and `recorded, control open`. A requirement row never takes either value, and no
interpretation proves compliance or closes a gap. An entry marked `recorded, control open` links an open control in
the [open-controls register](DECISIONS.md#open-controls-register).

| Decision | PRD item | Rows touched | Register status |
|---|---|---|---|
| D-015 | G27, p.12 privacy-sensitive data | E-9 (`partial`), D-7 (`partial`) | recorded, control open (P1) |
| D-016 | G9, p.10 queryable and p.11 data substrate | D-5 | decided |
| D-017 | G14, p.5 and p.12 human approval | M-11 (`partial`) | recorded, control open (P2) |
| D-018 | G15, p.12 write and read roles | D-8 (`partial`) | recorded, control open (P3) |
| D-019 | G16, p.9 and p.13 cost | E-6 (`gap`) | decided |
| D-020 | G17, p.16 checklist question on misuse of the platform | E-2 (`partial`) | decided |
| D-021 | G21, p.12 time budget | D-10 | decided |
| D-022 | p.11 OWASP items | M-10 (`partial`) | decided, with the U1 to U5 gaps open |

The G-register is not in the repository. The mapping from each G-id to a row is our reading and needs confirmation.
E-6 stays `gap`, E-2 stays `partial`, M-11 stays `partial` and H-1 stays `gap`.

## How to update this file

## P10 offline note (2026-10-20)

Re-read the Week 3 PRD, pages 11–13. No live call and no provider call. `LIVE_ENABLED` and `PROVIDER_ENABLED` stayed false.

Offline-met: X-1, X-2, X-5, X-6. X-3 and X-4 are externally unavailable: no cohort peer was assigned, and the project is completed independently and remotely. They are excluded from independent-project completion scope and stay unmet against the original PRD. [INTEGRATION_PACKET.md](INTEGRATION_PACKET.md) is the Q4 stub fallback, not peer integration. D-13 is met by [evals/results/d13-load.json](../evals/results/d13-load.json) on the Week 1 stub route, recorded in commit `17827fb`: 100 of 100, orchestration 90.13541795802303 seconds, stub LLM 0.0 seconds, storage 5991.5354876013225 rows per second. The bottleneck is the agent's 60-chat rolling minute, documented in [LOAD_TEST.md](LOAD_TEST.md). Measured stub spend is `$0`. This is not a real-provider benchmark. Q6 for the ATO packet stays unconfirmed. P10 stays in progress because X-3 and X-4 stay unmet. *(2026-10-21: D-13 was later downgraded to `partial`. See its row.)*

## P11 documentation pass (2026-10-20)

Re-read the original Week 3 PRD, submission table on pages 12–13, and [ROADMAP.md](ROADMAP.md) section 4 P11. No live call and no provider call. `LIVE_ENABLED` and `PROVIDER_ENABLED` stayed false. No allowlist edit. No commit and no push.

This pass updates the README, the architecture summary and diagram, [PROGRESS.md](PROGRESS.md), and this file so they match commit `17827fb` and the working tree. It does not move a row to `met` unless that row was already met. H-1 was re-checked and stays `gap`.

Engineering submission-table result:

- Repo guide: updated. Deployed link still missing, so S-7 stays partial.
- Threat model, users, contracts, three-category local evals, one local live agent: unchanged, previously evidenced.
- Architecture document: summary and diagram now distinguish scripted and stub edges from unverified live multi-agent edges. H-5 stays met as a document. It does not close live rows.
- Three vulnerability reports: still fixture drafts. M-10 stays partial.
- Cost analysis: unchanged, offline-met. D-13 `$0` is not blended into the `$0.05` reservation.
- Triage, ATO packet, failure drills: unchanged, offline-met. Q6 stays unconfirmed.
- Integration: unchanged. X-3 and X-4 stay unmet.
- Demo video and social post: excluded from this engineering pass. Not marked met.

Still open after this pass: H-1, S-1, S-5, S-6, S-7, E-1, E-2, E-3, E-4, E-6, G-1, G-2, G-5, and the live halves of M-1 through M-12, D-1 through D-4 and D-7. D-11 stays unmet because ADR-003 rejected a queue. D-13 stays met on the stub route only. *(2026-10-21: D-13 was later downgraded to `partial`. See its row.)*

## How to update this file

A checkpoint is not `met` here until [PROGRESS.md](PROGRESS.md) has the evidence. When a row moves, change its status
and name the file or the command. Do not mark a row met because the roadmap says the checkpoint is done.
