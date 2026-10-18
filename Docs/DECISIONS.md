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
| D-013 | Q8, by code reading at the pinned SHA, not by staff confirmation. Of the PRD-named items, no attacker-controlled outbound URL construction was identified for SSRF (A10): every outbound URL found is built from settings plus a fixed path. That is not proof SSRF is impossible. Vulnerable components (A06) and supply chain (LLM05) apply to the platform and are tracked as a P9 scan, not as attack cases. The rest apply and are mapped in THREAT_MODEL.md. The list names were checked against the official pages on 2026-10-17 and match. | P1 code reading | 2026-10-17 |

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
- **Known:** The PRD requires integration through the published contract alone, with no shared source access.
- **If no peer:** produce a stub-conformance packet, labeled as such (D-008), and record the gap.
- **Blocks:** the integration packet in P10 and the "build one, inherit another" lab.
- **Resolved by:** course staff or cohort coordination. Ask early, because it depends on another person's schedule.

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
