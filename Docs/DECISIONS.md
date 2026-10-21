# Week 3 decisions and open questions

The Week 3 PRD is authoritative. This file records what is decided, what is open, and what was assumed. See
[ROADMAP.md](ROADMAP.md) for the plan and [PROGRESS.md](PROGRESS.md) for status.

Rules:

- An ADR is added when a decision is made, never edited afterward. A change is a new ADR that supersedes the old one.
- An open question stays open until someone with authority answers it. Do not close one by assuming.
- Anything marked **(interpretation)** is our reading of the PRD, not a statement from it.

## 1. Decided

| Id | Decision | Source | Date |
|---|---|---|---|
| D-001 | The Week 3 PRD is authoritative over the roadmap. | User instruction | 2026-10-17 |
| D-002 | Roadmap is P0 to P11, revision 2, saved in `Docs/ROADMAP.md` of this repo (originally `docs/week3/ROADMAP.md` in the target repo). | User approval | 2026-10-17 |
| D-003 | Week 3 work is additive. `agent/`, existing evals, the golden set, the baseline file and `w2-eval-gate.yml` are not edited by default. | User instruction | 2026-10-17 |
| D-004 | CI starts at P0 and grows by checkpoint (ROADMAP section 6). No live or paid calls in CI. | User instruction | 2026-10-17 |
| D-005 | No new deployment infrastructure unless a decision here shows it is needed. | User instruction | 2026-10-17 |
| D-006 | Target allowlisting, synthetic data and cost controls exist and are tested before the first live attack (ROADMAP section 2.2). | User instruction | 2026-10-17 |
| D-007 | The platform reaches the target only over HTTP, whatever the repo layout. | Roadmap | 2026-10-17 |
| D-008 | Peer integration and stub conformance testing are labeled as different evidence. A stub is never called a peer. | User instruction | 2026-10-17 |
| D-009 | The four uncommitted Week 2 files (in the target repo) are left alone and kept out of Week 3 changes. | User instruction | 2026-10-17 |
| D-010 | Repo strategy B: this independent repo, target pinned by SHA, HTTP only. Paths `agent/`, `evals/` and `docs/week2/` in these docs are target-repo paths. See ADR-001. Resolves Q1 for P0 (PRD wording unconfirmed by staff). | User approval | 2026-10-17 |
| D-011 | Target access is the public OpenEMR module as a synthetic identity (ADR-002). Persisted SQLite state machine, no LangGraph (ADR-003). Per-role model config with distinct Red Team and Judge families (ADR-004). SQLite state (ADR-005). Own SQLite traces (ADR-006). Quick tunnel with reviewed manual edits, provisional (ADR-007). Python 3.12. Provider-side spend limits required before any live test. | User approval | 2026-10-17 |
| D-012 | P0 makes zero requests to the target. Reachability is UNVERIFIED until P3. | User instruction | 2026-10-17 |
| D-014 | The regression-scan SLO is 30 seconds for one `run_suite` of 100 synthetic cases, three repeats, on the in-process stub. The PRD requires a time budget and does not set the number. The measured operation is the suite execution, not a SQL SELECT and not `EXPLAIN QUERY PLAN`. `config/slo.yaml`. | P8, platform choice | 2026-10-20 |
| D-013 | Q8, by code reading at the pinned SHA, not by staff confirmation. Of the PRD-named items, no attacker-controlled outbound URL construction was identified for SSRF (A10): every outbound URL found is built from settings plus a fixed path. That is not proof SSRF is impossible. Vulnerable components (A06) and supply chain (LLM05) apply to the platform and are tracked as a P9 scan, not as attack cases. The rest apply and are mapped in THREAT_MODEL.md. The list names were checked against the official pages on 2026-10-17 and match. | P1 code reading | 2026-10-17 |
| D-016 | **(interpretation)** G9, p.10 observability: human-facing queries answer the six questions, and the Orchestrator reads the same persisted rows through `priority.py`. See entry D-016 below. | Remediation R6, our reading | 2026-10-21 |
| D-019 | **(interpretation)** G16, p.9 and p.13 cost: bounded spend is the requirement, enforced by the shared ledger and the operator approval. See entry D-019 below. | Remediation R6, our reading | 2026-10-21 |
| D-020 | **(interpretation)** G17, p.16 misuse of the platform: the default-deny allowlist is the control. See entry D-020 below. | Remediation R6, our reading | 2026-10-21 |
| D-021 | **(interpretation)** G21, p.12 time budget: the CI budget applies to one `run_suite` on the stub (D-014). See entry D-021 below. | Remediation R6, our reading | 2026-10-21 |
| D-022 | **(interpretation)** p.11 OWASP items: how the ledger reads each item. It does not close the PRD sentence that the suite must cover them. See entry D-022 below. | Remediation R6, our reading | 2026-10-21 |

### Recorded, control open

These three entries are not decisions. Each records where a PRD control sits and what it lacks. The status is
`recorded, control open`. No R6 text turns one of them into a decided, met or closed item. Each links an open control in
the [open-controls register](#open-controls-register).

| Id | Entry | Status | Open control | Date |
|---|---|---|---|---|
| D-015 | **(interpretation)** G27, p.12 data quality, "privacy-sensitive data". See entry D-015 below. | recorded, control open | P1 | 2026-10-21 |
| D-017 | **(interpretation)** G14, p.5 and p.12, human approval before publishing and before remediation. See entry D-017 below. | recorded, control open | P2 | 2026-10-21 |
| D-018 | **(interpretation)** G15, p.12, which agents can write exploits and which can only read. See entry D-018 below. | recorded, control open | P3 | 2026-10-21 |

### Interpretation entries (R6, 2026-10-21)

These are readings of ambiguous PRD sentences. They do not prove compliance and they close no gap. Quoted PRD text and
page numbers were checked on 2026-10-21 against `Docs/Week_3_AgentForge_Updated.docx.pdf`, where each page ends at its
"-- N of 17 --" marker. The G-register is not in this repository, and the mapping from each G-id to
requirement rows is our reading and needs confirmation. Every entry says "we read this as". None says an interpretation
satisfies a sentence. No code, config or test was changed to record them.

#### D-015 (interpretation). G27, p.12 data quality, "privacy-sensitive data". Status: recorded, control open (P1)

- **Not proven (first).** That no unscanned write can reach the store. The store has no PHI scan, so this is not a
  store-level privacy control.
- **PRD sentence and page.** p.12: "Data-quality checks: required fields, uniqueness, referential integrity,
  privacy-sensitive data." The PRD does not say where the privacy check must sit.
- **Reading.** We read the requirement as being located at the executor and content scans, which is where a scan exists
  today.
- **Evidence that exists today.** `src/agentforge/safety/phi.py`, the executor scan in `src/agentforge/evals/executor.py`,
  `src/agentforge/safety/content.py`, and `test_phi_blocks_store`.
- **Residual risk.** Any in-process caller or direct SQL can write unscanned text. See open control P1.
- **Will not build.** A store-boundary scan in `src/agentforge/store/records.py`.
- **Reopen trigger.** A decision that the PRD requires a store-level scan. That becomes a new checkpoint after R6.
- **Requirement rows touched and their status.** E-9 is `partial` as set in R5, with its original evidence and the P1
  sentence. D-7 stays `partial`. Neither is annotated as met under this interpretation, and R6 does not change either
  status. D-7 carries only the words "control unproven, see D-015".
- The U2 gap (PHI in target logs, traces and provider payloads) is a different control. G27 is the store. U2 is the
  target. This entry does not touch U2.

#### D-016 (interpretation). G9, p.10 and p.11, "queryable" and "data substrate"

- **PRD sentence and page.** p.10, regression harness: "Store confirmed exploits in a versioned, queryable format".
  p.11, observability layer: "It is the data substrate your Orchestrator Agent reads. Design it accordingly." The two
  sentences are on different pages and in different sections.
- **Reading.** We read this as: human-facing queries answer the six questions, and the Orchestrator reads the same
  persisted rows through `priority.py`.
- **Evidence that exists today.** `src/agentforge/observe/queries.py`, `src/agentforge/orchestrator/priority.py`,
  `scripts/observe.py` and `tests/test_p8_queries.py`.
- **Not proven.** That the human `answers` path and the Orchestrator's read path agree.
- **Residual risk.** They are two code paths over the same tables and could diverge.
- **Will not build.** A loop call to `answers`.
- **Reopen trigger.** A divergence found between the two paths, or an instruction that one path must serve both.
- **Requirement rows touched and their status.** D-5 stays `met`, with a "met under interpretation D-016" note in its
  evidence cell. The status is unchanged.

#### D-017 (interpretation). G14, p.5 and p.12, human approval before publishing critical or high findings and before remediation. Status: recorded, control open (P2)

- **Not proven (first).** That the named person approved, or that anyone did.
- **PRD sentence and page.** p.5: "A system that autonomously files vulnerability reports, recommends patches, or
  triggers remediation workflows must have clearly defined trust boundaries and human approval gates." p.12: "what
  human approval is required before a finding is published." Neither sentence names critical or high severity. That
  scope is our reading.
- **Reading.** We read the approval record as a non-blank approver label plus the YAML gate. That is the record format,
  not proof of approval.
- **Evidence that exists today.** `src/agentforge/agents/approval.py` and `tests/test_p7_gates.py`.
- **Residual risk.** The label can be spoofed in-process, so a gate pass shows a label was supplied. See open control
  P2. M-11 stays `partial`.
- **Will not build.** Authenticated principals.
- **Reopen trigger.** A decision that the PRD requires attributable approval. That becomes a new checkpoint.
- The same limit applies to a `client_verified` or `recorded_verified` report. Neither label implies a human approved
  it, and the report text keeps its "a human must approve" sentence.
- **Requirement rows touched and their status.** M-11 stays `partial` and carries only the words "control unproven, see
  D-017". R6 changes no status.

#### D-018 (interpretation). G15, p.12, "which agents can write exploits, which can only read". Status: recorded, control open (P3)

- **Not proven (first).** Enforcement against the process owner.
- **PRD sentence and page.** p.12: "Define access controls: which agents can write exploits, which can only read
  them, and what human approval is required before a finding is published."
- **Reading.** We read the in-process `Grant` plus the documented SQL-owner limit as defining who writes.
- **Evidence that exists today.** `src/agentforge/store/access.py`, `tests/test_p9_access.py`,
  [ACCESS_CONTROL.md](ACCESS_CONTROL.md) and ADR-005.
- **Residual risk.** The process owner or direct SQL bypasses grants (ADR-005). See open control P3.
- **Will not build.** Database roles.
- **Reopen trigger.** A decision that the PRD requires enforcement against the process owner.
- **Requirement rows touched and their status.** D-8 is `partial` as set in R5, with its original evidence and the P2
  sentence, because its approval-before-publication part rests on the unproven label in open control P2. D-8 is not
  annotated as met under this interpretation, and R6 does not change its status.

#### D-019 (interpretation). G16, p.9 and p.13, cost

- **PRD sentence and page.** p.9: "Halting or redirecting when cost is accumulating without producing signal" and
  "LLM cost is also a factor as this can run up tokens very quickly." p.13: "Actual dev spend and projected production
  costs for running the adversarial platform at 100 / 1K / 10K / 100K test runs." The PRD states no spend cap.
- **Reading.** We read bounded spend as the requirement, enforced by the shared ledger and the operator approval. The
  provider-side cap is not a literal PRD sentence. It comes from D-011 and Q13.
- **Evidence that exists today.** `src/agentforge/safety/budget.py`, `src/agentforge/safety/ledger.py`,
  `src/agentforge/safety/spend_limits.py` and `config/spend_limits.yaml`.
- **Not proven.** That any provider key has a monitored limit.
- **Residual risk.** The 2026-10-19 episode, where the shared key had passed its own limit with no repo-side
  attestation.
- **Will not build.** A provider-side attestation. The cap is the R8 operator gate.
- **Reopen trigger.** The key owner confirms a monitored limit, or the PRD is read as requiring one before any live run.
- **Requirement rows touched and their status.** E-6 stays `gap`.

#### D-020 (interpretation). G17, p.16, "turned against systems it should not attack"

- **PRD sentence and page.** p.16, Appendix pre-search checklist, item 9: "How do you prevent the adversarial platform
  from being turned against systems it should not attack?" This is a planning question in the checklist, not a
  requirement sentence, so reading it as a requirement is itself our interpretation.
- **Reading.** We read the default-deny allowlist as the control.
- **Evidence that exists today.** `src/agentforge/safety/allowlist.py`, `config/allowlist.yaml`, `tests/test_allowlist.py`
  and `.github/CODEOWNERS`.
- **Not proven.** That changes to the allowlist are reviewed.
- **Residual risk.** CODEOWNERS has no effect without branch protection (G-5).
- **Will not build.** Branch protection, which is an R7 operator setting.
- **Reopen trigger.** Branch protection is confirmed on, or a decision that the PRD requires reviewed changes.
- **Requirement rows touched and their status.** E-2 stays `partial`.

#### D-021 (interpretation). G21, p.12, "complete within a defined time budget... verify it in CI"

- **PRD sentence and page.** p.12: "Regression runs that scan the full exploit database must complete within a defined
  time budget — document this SLO and verify it in CI."
- **Reading.** We read the CI budget as applying to one `run_suite` on the stub (D-014).
- **Evidence that exists today.** `config/slo.yaml`, `scripts/check_slo.py` and [INDEXES.md](INDEXES.md).
- **Not proven.** SQL query time or live-database time.
- **Residual risk.** A scan-heavy production query could be slow while CI stays green.
- **Will not build.** A SQL timer.
- **Reopen trigger.** A decision that the PRD requires a database-level timer.
- **Requirement rows touched and their status.** D-10 stays `met`, with a "met under interpretation D-021" note in its
  evidence cell. The status is unchanged.

#### D-022 (interpretation). p.11 OWASP items

- **PRD sentence and page.** p.11: "The attack suite must cover the OWASP Top 10 web vulnerabilities relevant to the
  Clinical Co-Pilot (broken access control, injection, insecure design, vulnerable components, auth failures, logging
  failures, SSRF) in addition to the OWASP LLM Top 10 (prompt injection, insecure output handling, sensitive
  information disclosure, excessive agency, supply-chain risks). Map each test case to its OWASP category in the eval
  dataset."
- **Reading.** We read the R4 ledger [`evals/owasp_coverage.json`](../evals/owasp_coverage.json) as a coverage record.
  A06 and LLM05 are platform scans, A10 is a code reading, and A03 is narrowed to prompt injection. A09 and A04 are
  unverified properties. A01 is offline only, with no target outcome. LLM02, LLM06 and LLM08 are partially exercised,
  and the LLM08 case is a response-claim proxy.
- **Evidence that exists today.** The ledger, the 11 cases, `evals/results/offline-latest.json` and
  `tests/test_r4_offline.py`.
- **Not proven.** That any of the OWASP items the PRD names is covered on the deployed target. None of this closes the
  p.11 "must cover" sentence in full.
- **Open gaps, unresolved.** U1 (UI output handling), U2 (target logging and data flow), U3 (tool-invocation
  visibility), U4 (design assessment) and U5 (target components and other injection or request classes). R10 is named
  only as the public-target repeat of the chat-observable halves.
- **Hosting assessment.** Each is conditional and none is confirmed. U1 needs a reachable target UI (after R7) and a
  browser-level check that R10's scope does not include today. U2 can ride on R7 only as a record of whether operator
  log access exists, and reviewing logs needs a known attack sequence from R9 or R10. U3 depends on a target-side
  trace, log or tool-call field that nothing here creates. The static half of U5 (A06, LLM05) can ride on R7 given
  repository or SBOM access, while A03 beyond prompt injection and A10 need a live host. U4 needs a
  documentation-only checkpoint. No cycle has been amended.
- **Residual risk.** The PRD sentence stays open. LLM06's privacy half is U2 and is not addressed by the D-015 entry.
- **Will not build.** Any case labeled A09 or A04, or any claim that a ledger row is satisfied.
- **Reopen trigger.** Your decision to add checkpoints for U1 to U5, or a PRD reading that excludes one of them. This
  entry is not that decision.
- **Requirement rows touched and their status.** M-10 stays `partial`. No U-item has a roadmap checkpoint.

### Open-controls register

Each control has status `open`. This register is where an unproven control stays visible. R6 builds none of the
closing steps.

| Control | What is unproven | What would address it | Status |
|---|---|---|---|
| P1, store-level privacy | Unscanned text can be written to the store by any in-process caller or by direct SQL. The scans sit at the executor and content boundary, not at the store. | A store-boundary scan, or a PRD reading that excludes the store. R6 does neither. | open |
| P2, approver identity | `approved_by` is a non-blank label, not an authenticated principal, so a recorded approval does not show a named person approved. | Authenticated approvers, or an attested out-of-band approval record. R6 builds neither. | open |
| P3, write authority against the process owner | In-process grants do not bind the process owner or direct SQL (ADR-005). | Database-level roles, or an accepted documented limit. R6 builds neither. | open |

### Residual-risk register

One list. It collects the residual risks above, the open controls P1 to P3, one line per open OWASP gap, and the R3 and
R4 limits.

- P1, P2 and P3 above, each `open`.
- U1: the deployed UI's rendering of an answer (`textContent`) and the source-viewer CSP are not observed.
- U2: whether the target logs enough to reconstruct an attack, and PHI in its logs, traces and provider payloads, are
  not observed.
- U3: whether a tool call happened is not observed. The LLM08 case is a response-claim proxy and says nothing about
  tool invocation.
- U4: the target's design properties (A04) are known by code reading only.
- U5: the target's components and other injection or request classes (A06, LLM05, A03 beyond prompt injection, A10)
  are not observed.
- The executor passes a canary case on an empty 200 body. The offline runner guards against it. That executor path is
  not changed. (The executor's separate `question_length` grading bug, which graded against the response length, was
  fixed on 2026-10-21 and is covered by tests.)
- `grade_patient_boundary` fails a refusal that names the other patient id and contains the word "authorized" (for
  example "not authorized for patient 101"). The `seed-tm-id-1` and `seed-tm-ex-2` safe bodies avoid the id, so the
  gate does not hit it. The grader is not changed, because that would change graded outcomes.
- Fix-validation lines state their replay basis, but the label does not gate `fixed`, publication or the `resolved`
  status in `observe/queries.py`. A `stub`-based `fixed` still reads as resolved on the dashboard. Owners: R11 (a
  published report must cite a verified basis) and R12 (journaled client replay).
- `client_verified` has no journal check, because client replay is not journaled. It proves transport and sequence
  provenance only, not a validated fix.
- `recorded_verified` and `client_verified` are proven only on constructed facts until R9 and R12.
- A resumed campaign reports `unverified` for a sequence started before the resume.
- The D-016 query paths could diverge. The D-019 provider-side limit is unattested. The D-020 allowlist review is not
  enforced. The D-021 budget measures the stub suite, not SQL time.

## 2. Open questions

Each question lists the options, what it blocks, and who or what answers it. None has an answer yet.

### Q1. Repo strategy
- **Question:** Same repo (A), new repo with the target pinned (B), or new repo with the target by URL only (C)?
- **Compared in:** ROADMAP section 2.5.
- **Why open:** The PRD says "Independent code repo" and we have not confirmed whether option A satisfies it.
- **Blocks:** P0 onward (where CI and code live).
- **Resolved by:** P0 ADR, plus confirmation of the PRD wording from the course staff if option A is preferred.

### Q2. Stable public URL for the target
- **Question:** Is a rotating Cloudflare quick tunnel acceptable for "deployed target URL with every checkpoint"?
- **Known:** The tunnel hostname changes on each start, and the allowlist must be edited each time.
- **Options:** keep the quick tunnel; a named tunnel (stable hostname, no new hosting); the untested VPS path in `deploy/`.
- **Blocks:** every checkpoint submission, and allowlist stability.
- **Resolved by:** staff confirmation on what counts as deployed, then a P0 ADR. Prefer the lowest-infrastructure option that
  gives a stable hostname.

### Q3. Where the platform itself runs
- **Question:** Laptop, CI runner, or a server?
- **Known:** The PRD requires live tests against the deployed target, not that the platform be hosted.
- **Blocks:** scheduled and target-change triggers (P6, P9), and where protected secrets live.
- **Resolved by:** P0 ADR.

### Q4. Peer integration
- **Question:** Does a peer with an independently built agent exist, and does the cohort run the integration week?
- **Known:** The PRD requires integration through the published contract alone, with no shared source access. The project is being completed independently and remotely. No cohort peer was assigned.
- **If no peer:** produce a stub-conformance packet, labeled as such (D-008), and record the gap. That fallback is written. It is not peer integration.
- **Status:** X-3 and X-4 are externally unavailable and excluded from independent-project completion scope. They stay unmet against the original PRD. Staff confirmation is not available and is not assumed.
- **Blocks:** the peer half of the P10 integration packet and the "build one, inherit another" lab.

### Q5. MVP versus final timing of ambiguous deliverables
- **Question:** Are the demo video, AI cost analysis and vulnerability reports due at MVP?
- **Known:** The PRD table says "one demo video per submission" and gives no per-checkpoint dates for the others.
- **Current plan:** video at each submission if required, actual spend at MVP, full cost analysis and 3+ reports at Final.
- **Resolved by:** staff confirmation. Until then, plan for the stricter reading where cheap.

### Q6. Two "evidence packet" artifacts
- **Question:** Are the Architecture Defense evidence packet and the ATO-style evidence packet separate artifacts?
- **Known:** The PRD says the ATO packet is "separate from the Architecture Doc". The Defense packet lists diagram, schemas,
  trust boundaries and failure modes.
- **Current plan (interpretation):** a draft at Defense, a full ATO packet at Final.
- **Resolved by:** staff confirmation or a later ADR.

### Q7. Which data-platform requirements apply
- **Question:** Do the queue, SQL index, migration and SLO requirements apply?
- **Known:** The PRD words them conditionally ("if the platform uses a queue", "if the exploit database uses SQL").
- **Plan:** treat the SQL and migration requirements as applicable. Decide on a queue in the state-store ADR.
- **Resolved by:** the P2 and P6 ADRs.

### Q8. OWASP applicability
- **Question:** Which OWASP Top 10 and LLM Top 10 items apply to the Co-Pilot (for example SSRF, supply chain)?
- **Resolved:** D-013, from reading the target code at the pinned SHA. The per-item dispositions and reasons are in
  THREAT_MODEL.md. Staff confirmation was not sought; the resolution is a code reading, and it is void if the pin moves.

### Q9. Agent framework
- **Question:** Hand-written state machine (as in Weeks 1 and 2) or an existing framework such as LangGraph?
- **Known:** The PRD requires a multi-agent system with durable coordination and state. It does not name a framework.
- **Resolved by:** P0 ADR, weighing resumable state, tracing, dependency weight and consistency with Week 2.

### Q10. Model assignment per agent role
- **Question:** Which models power the Red Team, Judge, Orchestrator and Documentation agent?
- **Known:** Commercial models may refuse offensive tasks. The Judge must be independent of the attacker. The PRD wants cost
  and refusal behavior addressed.
- **Not yet checked:** which providers refuse which attack types. This needs a small, approved, capped probe, not a guess.
- **Resolved by:** P0 ADR, informed by a budgeted probe in P4.

### Q11. Observability backend
- **Question:** Extend the existing `traces.db` approach, or adopt a hosted tool such as Langfuse?
- **Resolved by:** P0 ADR. The PRD asks for inter-agent traces and per-agent cost.

### Q12. Exploit store and queue technology
- **Question:** SQLite or a server database? Is a queue needed?
- **Candidate:** SQLite, because the Week 2 agent already uses it and it adds no infrastructure.
- **Resolved by:** ADR-005 (SQLite, no queue). P2 builds the schema on that decision and does not reopen it.

### Q13. Provider-side spending limits
- **Question:** Can a hard spending limit be set on each provider key?
- **Known:** The Week 2 budget was an internal reservation, not a billing ceiling.
- **Blocks:** the first live run (D-006).
- **Resolved by:** the operator checks the provider dashboards. This cannot be verified from the repo.

## 3. Assumptions to verify

| Id | Assumption | How to verify |
|---|---|---|
| A-001 | The deployed target is demo data only, with no real PHI. | Check fixtures and the deploy docs before the first live run. |
| A-002 | The target's key has spend headroom for attack traffic (about $0.05 per chat). | Provider dashboard. |
| A-003 | The target's rate limiter and nonce cache tolerate the platform's request rate. | Read `agent/app/gateway.py` and run a small approved probe. |
| A-004 | The platform can obtain a synthetic test identity and signing material without editing target code. | Read `agent/AUTHZ_PROOF.md` and the module docs in P0. |
| A-005 | The target's behavior is stable enough that pinning a commit makes replays meaningful. | Replay checks in P3. |

## 4. ADR log

ADRs live in [adr/](adr/README.md): 001 repo strategy, 002 target access, 003 coordination, 004 models per role,
005 state store, 006 observability, 007 URL handling. Format for each entry (see also adr/TEMPLATE.md):

```
### ADR-NNN: <title>
- Status: proposed | accepted | superseded by ADR-MMM
- Date:
- Context:
- Options considered (with what each was rejected for):
- Decision:
- Consequences and risks:
- Verification that the decision holds:
- Related questions: Q#
```

## 5. Interface changes log

Every change to an inter-agent message schema or the store schema is recorded here and in its migration note
(PRD requirement). The note lives in [migrations/](migrations/).

| Date | Schema | Version change | Breaking? | Migration note |
|---|---|---|---|---|
| 2026-10-17 | Message schemas: CampaignRequest, AttackResult, Verdict, ConfirmedExploit, five error schemas | none to v1 | no | [0001](migrations/0001-initial-schema.md). First publication, in `contracts/v1/` |
| 2026-10-17 | Store schema: exploits, regression cases, run logs, coverage metrics | none to 0001 | no | [0001](migrations/0001-initial-schema.md) |
| 2026-10-18 | RecordedTranscript added under contracts/v1. Optional relative to the four P2 messages. Not a message between agents | none to v1 | no | [0002](migrations/0002-agent-spend.md). The transcript is not a store table |
| 2026-10-18 | Store schema: agent_spend, reserved and incurred as separate columns | 0001 to 0002 | no | [0002](migrations/0002-agent-spend.md) |
| 2026-10-18 | RecordedTranscript: optional attacks_before, attacks_after, attack_cap. Verdict: optional needs_human_review | none to v1 | no | Optional fields. No version bump. Existing records and messages stay valid |
| 2026-10-19 | Store schema: regression_cases lifecycle cache, regression_runs, reports, regression_detections | 0003 to 0004 | no | [0004](migrations/0004-regression-lifecycle.md). Contracts stay v1. No RegressionTrigger schema |
