# Week 3 roadmap: AgentForge Adversarial AI Security Platform

Status: approved revision 2 (P0 to P11), adapted for the independent `agentforge-platform` repo on 2026-10-17.
P0 is implemented but not committed. Later checkpoints are not implemented. Paths such as `agent/`, `evals/`,
`scripts/w2/`, `docs/week1/`, `docs/week2/`, `deploy/`, `loadtest/` and `.github/workflows/w2-eval-gate.yml` refer to
the **target repository** (`Sabeehq11/openemr-base-clean`, pinned at `9f03654`), not to this repo, unless stated.

Authority: the Week 3 PRD ("AgentForge: Adversarial AI Security Platform", 17 pages) is authoritative. If this file
disagrees with the PRD, the PRD wins and this file must be corrected. Interpretations of the PRD are marked
**(interpretation)** and tracked in [DECISIONS.md](DECISIONS.md). Progress is tracked in [PROGRESS.md](PROGRESS.md).

Labeling rule (carried over from Week 2): anything not yet built is **(planned)** and must not be described as
runnable in a README, a demo or a report.

## 1. Starting state (verified 2026-10-17, read-only)

Reusable from Weeks 1 and 2 (branch `week2-agentforge`, HEAD `9f03654`):

| Asset | Where |
|---|---|
| Target: Co-Pilot agent, signed-request gateway, per-call patient authorization, verifier, HMAC audit chain, SQLite traces | `agent/` |
| Target endpoints | `/v1/chat`, `/v1/w2/chat`, `/v1/w2/documents`, `/v1/w2/documents/{id}/page`, `/v1/w2/retrieve`, `/ready` |
| OpenEMR module (chat dock, upload, source viewer) | `interface/modules/custom_modules/oe-module-copilot` |
| Eval machinery: registry, harness, stub and live tiers, 67 guard cases, 50-case golden set, baseline gate | `evals/` |
| CI pattern: lint, mypy baseline, coverage floor 90%, pip-audit, secret scan, Bandit, eval gate | `.github/workflows/w2-eval-gate.yml`, `scripts/w2/` |
| Spend-approval pattern (token bound to exact budget, hard ceiling) | `scripts/w2/measure.py` |
| Load-test tooling with a mock provider | `loadtest/` |
| Deployment: Cloudflare quick tunnel (URL changes on each start), untested VPS path | `scripts/copilot/deploy_w2.sh`, `deploy/` |
| Prior docs | `W2_ARCHITECTURE.md`, `docs/week1/`, `docs/week2/` |

Not present (the PRD requires them):

- `THREAT_MODEL.md`, `ARCHITECTURE.md`, root `USERS.md`, `/contracts`.
- Any Red Team, Judge, Orchestrator or Documentation agent.
- Live adversarial runs. The existing 67 cases are guard tests against a scripted model, not attacks on the live target.
- A stable public URL. The PRD makes a deployed URL a hard gate on every checkpoint.

Uncommitted at the start of Week 3 (four unrelated files, left alone): `docs/week2/DEMO_SCRIPT.md`,
`evals/results/gate-latest.md`, `evals/results/w2-golden-latest.json`, `evals/results/w2-golden-latest.md`.

Cost facts that shape the plan:

- A Week 2 chat costs about $0.05 on the target's key (mean 0.0498 USD, `docs/week2/PERFORMANCE.md`). 100 live attacks
  are roughly $5 on the target's key before any attacker or judge model cost. Multi-turn sequences cost more.
- The Week 2 "$1.50 budget" is an internal reservation, not a billing ceiling. Real cost control needs a
  provider-side spending limit on every key.

## 2. Cross-cutting rules

### 2.1 Preservation

- Tag `w1-baseline` and the `week2-agentforge` history are not rewritten.
- `agent/`, the 67 stub cases, the 50-case golden set, `evals/w2/baseline.json` and `w2-eval-gate.yml` are not edited by
  default. Week 3 work is additive.
- The four uncommitted files above stay out of Week 3 changes.
- An unavoidable edit to the target goes through a named seam and a migration note, as in Week 2, and is recorded in
  DECISIONS.md.

### 2.2 Pre-attack safety envelope

No live request leaves the platform until every control below exists and has a passing test. This is a hard
precondition for the first live run (P3) and everything after it.

| Control | Requirement |
|---|---|
| Target allowlist | Explicit, version-controlled list of scheme, host, port and path prefix. Enforced at one HTTP chokepoint that every agent must use. Default deny. Off-list redirects are refused and logged. Adding an entry is a reviewed change (CODEOWNERS or equivalent), never automatic. The quick-tunnel hostname rotates, so each new URL is a deliberate reviewed edit. |
| Target identity check | Before each run, confirm the target reports the expected synthetic-demo fingerprint (for example `/ready` plus a known fixture patient). Guards against a stale or wrong URL. |
| Synthetic data only | The target holds only demo patients (`copilot_doc_a` fixtures). Platform fixtures, payloads and stored transcripts are synthetic. Reuse the `test_w2_phi_static_unit.py` pattern. Transcripts that quote target output are scanned before storage. |
| Cost controls | Per-run and per-day USD caps and a per-run attack-count cap, set through an approval token in the `measure.py` style. A provider-side spending limit on every API key. Spend is metered per agent, including target-side spend caused by the attacks. A kill switch halts before the next call. A request-rate cap protects the target. |
| Human approval | Required for any run above the default cap, any new allowlist entry, and any load test. |

CI never makes live or paid calls. Live runs are manual or scheduled, use protected secrets, and never run on forked PRs.

### 2.3 CI is incremental

CI starts at P0 and each checkpoint adds jobs. No job is removed. Jobs that read secrets run only on protected
branches. The ladder is in section 6.

### 2.4 No unnecessary deployment infrastructure

The deployed target already exists (Week 2). Week 3 adds no new hosting unless a decision in DECISIONS.md shows it is
needed. The PRD requires a publicly accessible target with every checkpoint and requires the platform to run live
tests against it. It does not say the platform itself must be hosted. Where the platform runs (laptop, CI, server) is
open: DECISIONS.md, Q3. The target's URL stability is a separate question: DECISIONS.md, Q2.

### 2.5 Repo strategy: compared here, decided in P0 (option B, see [ADR-001](adr/001-repo-strategy.md))

The PRD says "Independent code repo". No choice is made in this file.

| Option | Pros | Cons and risks |
|---|---|---|
| A. Same repo, new top-level package | Simplest. Reuses CI and `evals/` directly. Preserves history. | May not satisfy "independent code repo". Blurs the trust boundary, because the platform could import target internals. |
| B. New repo, target pinned by tag or submodule | Meets "independent". Target version is traceable. | Submodule friction. Temptation of source-level coupling. |
| C. New repo, target by URL only | Cleanest black-box boundary. Mirrors a real external red team. | Needs a copy of target contracts or fixtures. Target changes need a separate record. |

Decision criteria for the P0 ADR: PRD independence, black-box boundary, CI reuse, history preservation, cost of
coordinating changes across repos. Under every option the platform reaches the target only over HTTP.

## 3. MVP versus final

PRD schedule: Architecture Defense (4 hours after kickoff), MVP (Tuesday 11:59 PM), Final (Friday noon). The deployed
target URL is submitted with every checkpoint (PRD hard gate).

| Requirement | Architecture Defense | MVP | Final |
|---|---|---|---|
| Build-versus-configure record | Required (PRD) | Kept | Final |
| Evidence packet: agent diagram, message schemas, trust boundaries, known failure modes | Required (PRD) | Updated | Complete |
| Deployed target URL | Required | Required | Required |
| `THREAT_MODEL.md` with ~500-word summary first | | Required | Updated |
| Attack suite in `evals/`, results from 3+ attack categories | | Required | Extended |
| One agent role running live against the deployed target | | Required | All four roles |
| `ARCHITECTURE.md` with ~500-word summary, named agents, diagram | | Required (Stage 4) | Complete, with AI-use disclosure |
| Versioned contracts in `/contracts`, error schemas, contract tests | Draft schemas | First version | Full coverage, both sides tested |
| Regression harness, Documentation agent, 3+ vulnerability reports | | | Required |
| Orchestrator, cost halting, observability answers | | Prototype at most | Required |
| Baselines, 100-case load test, regression SLO verified in CI | | | Required |
| Triage lab, ATO-style evidence packet, integration packet | | | Required |
| AI cost analysis (100 / 1K / 10K / 100K) | | Actual spend so far **(interpretation)** | Required |
| Demo video (3 to 5 minutes) | | See section 5 | Required |
| Social post | | | Required (PRD: Final only) |

Rows marked **(interpretation)** or "See section 5" need confirmation. The PRD's submission table lists some
deliverables without saying which checkpoint they are due at.

## 4. Checkpoints

Each checkpoint lists scope, dependencies, verification and the CI added.

### P0. Foundations and decisions (Architecture Defense)

- **Scope**
  - Repo-strategy ADR (section 2.5).
  - Build-versus-configure record for Burp Suite, OWASP ZAP, Semgrep, Garak and commercial red-team platforms: what each
    covers, where it falls short here, why custom code is or is not justified per agent role. Include plain
    deterministic tooling for replay and fuzzing.
  - ADRs for agent framework, model per role, state store, observability backend.
  - Target freeze: record the exact target commit, the current public URL, and every change made to bring the target
    into a testable state (PRD Stage 1 asks for this).
  - Safety-envelope skeleton: allowlist file, HTTP chokepoint stub, cost-cap configuration. No live calls.
  - Draft Architecture Defense evidence packet: agent diagram, message schema list, trust boundaries, failure modes.
- **Depends on:** nothing.
- **Verification**
  - Each ADR names the alternatives rejected and why.
  - Target reachability is **UNVERIFIED** in P0. P0 makes zero target requests. The agent's `/ready` is private by
    design (the tunnel serves OpenEMR only), so the later check is a read-only GET of the public OpenEMR login page
    through the chokepoint, deferred to P3 (no model call).
  - A unit test shows the allowlist denies by default.
- **CI added:** lint, secret scan, markdown and link check. Reuse the pinned tools from Week 2. Secret scanning starts
  here because the platform will hold API keys.

### P1. Threat model and users

- **Scope**
  - `THREAT_MODEL.md` (~500-word summary first) and `USERS.md`.
  - All six PRD categories: prompt injection (direct, indirect, multi-turn); data exfiltration (PHI leakage,
    cross-patient exposure, authorization bypass); state corruption; tool misuse; denial of service (token
    exhaustion, loops, cost amplification); identity and role exploitation.
  - Per category: attack surface, impact, difficulty, whether existing defenses address it.
  - Mapping to OWASP Top 10 and OWASP LLM Top 10.
  - Target-specific surfaces: PDF and intake upload (indirect injection through the vision model), guideline
    retrieval, `/page` and the source viewer, the signed gateway and nonce cache, the in-memory rate limiter.
  - Threats to the platform itself, such as a malicious target response or a prompt-injected transcript steering the
    Judge or the Documentation agent.
  - Mark OWASP items that do not apply and say why. Check SSRF against the target's code before claiming either way.
  - `USERS.md`: users, workflows, use cases, and why automation is the right solution.
- **Depends on:** P0.
- **Verification**
  - Every category has all four attributes.
  - Defenses are cited to specific files (for example the verifier, `authz.py`).
  - Every OWASP area the PRD lists is covered or explicitly out of scope with a reason.
- **CI added:** check that every threat category ID referenced by a case exists in the threat model.

### P2. Contracts and data model

- **Scope**
  - v1 JSON Schemas in `/contracts` for Orchestrator to Red Team, Red Team to Judge, Judge to Documentation, and
    Judge to regression harness.
  - Typed error schemas for the PRD failure modes: target unreachable, budget exceeded, judge timeout, no findings in
    window, regression detected.
  - Migration-note convention and a per-schema changelog.
  - Data model: exploit records, regression cases, agent run logs, coverage metrics. Constraints: unique ID, required
    fields (severity, attack category, reproduction steps, observed behavior, expected behavior), a normalized
    attack-sequence hash to reject duplicates.
  - Indexes for severity, attack category and system version. Migration tool.
  - Access control per data class: which agents write exploits, which only read, what human approval precedes
    publication.
  - SQLite is a candidate (the Week 2 agent already uses it, no new infrastructure). Decided in an ADR, not here.
- **Depends on:** P1 (categories drive the enums).
- **Verification**
  - Producer-side and consumer-side contract tests both pass for each message.
  - A breaking change without a version bump fails.
  - A migration adds a field to existing records with no data loss.
  - Duplicate and incomplete exploit inserts are rejected.
- **CI added:** contract tests, schema-diff check, migration tests.

### P3. Seed attack suite and deterministic executor

- **Scope**
  - Case format: category and subcategory, input sequence, expected safe behavior, observed behavior
    (pass, fail, partial), severity, exploitability, regression flag, OWASP ID, and a tag of boundary, invariant or
    regression risk (PRD: every case must exercise one; static payload lists do not satisfy this).
  - Executor that reaches the target only through the allowlist chokepoint, as the synthetic test identity.
  - Deterministic first-layer checks: canary strings, PHI patterns, patient-ID boundaries, tool-call allowlist.
  - At least 3 attack categories (PRD floor); aim for 5 or 6, including indirect injection through upload,
    cross-patient access and cost amplification.
  - Cover the PRD's OWASP Top 10 and LLM Top 10 items that apply, each case mapped in the dataset.
  - Synthetic fixtures with a PHI scan.
  - Precondition: the full safety envelope (section 2.2) is working and tested before the first live run.
- **Depends on:** P2 and the safety envelope from P0.
- **Verification**
  - A dry-run mode with no network passes in CI.
  - One approved live run against the deployed target stores results under `evals/`.
  - Replays give the same deterministic verdict.
  - A deliberately weakened local target makes the checks fail (the `scripts/w2/gate_demo.sh` approach).
- **CI added:** suite schema validation, synthetic-data scan, allowlist tests. No live calls.

### P4. Judge prototype first, then Red Team seed

- **Scope**
  - Judge first: deterministic rules, then an LLM verdict only for ambiguous cases, from a different model family than
    the attacker. The Judge is independent of attack generation (PRD).
  - Hand-labeled ground-truth set with benign and near-miss examples.
  - Judge consistency checks across runs, and a drift procedure (the PRD requires documenting how a drifting judge is
    detected and corrected).
  - Minimal Red Team that mutates seeds under a per-run budget.
  - Per-agent cost metering and the kill switch.
- **Depends on:** P3 and the P0 model ADR.
- **Verification**
  - Measured Judge precision, recall and false-positive rate on the labeled set.
  - Invariant test: the Judge never approves a confirmed successful exploit as safe.
  - A cap-halting test shows the run stops before the next call.
  - One live run produces a stored, traceable finding.
  - Nothing in the run reaches a host that is not on the allowlist.
- **CI added:** Judge evaluation on the labeled set using recorded or stub model responses. Live model runs stay manual.

### P5. MVP pack

- **Scope**
  - `ARCHITECTURE.md` (~500-word summary first): each agent named with role, inputs, outputs, trust level; diagram;
    communication design; trust boundaries; AI-use disclosure (every AI-powered role, the deterministic check or human
    approval after each AI decision, remaining risk); rate limits and auth requirements for every external API, with
    the chosen backoff, queue or abort behavior.
  - README: setup guide, architecture overview, deployed link, how to run the platform against the live target.
  - Deployed target URL. Spend recorded so far.
- **Depends on:** P1 to P4.
- **Verification**
  - A fresh clone runs a dry-run campaign from the README.
  - Every MVP hard gate is ticked against the PRD.
- **CI added:** documentation checks only (links, diagram sources).

### P6. Orchestrator and multi-agent run

- **Scope**
  - Orchestrator reads coverage gaps, open high-severity findings and recent regressions, and picks the next campaign.
  - Persisted run state. If a queue is used: depth monitoring and a stated behavior when it backs up.
  - Typed handling of rate-limit responses (backoff, queue or abort).
  - Cost-aware halt or redirect when spend produces no signal.
  - Fallback when there is no clear priority. Trigger for regression runs when the target version changes.
  - Red Team: novel generation, mutation of partial successes, multi-turn sequences.
- **Depends on:** P2 to P4.
- **Verification**
  - An end-to-end run traced under one correlation ID through all agents.
  - Killing an agent mid-run yields a typed error and a resumable state.
  - A novelty measure shows variants differ from seeds and from each other.
  - The no-priority fallback is tested.
- **CI added:** state-machine tests with scripted agents (no model calls).

### P7. Regression harness, Documentation agent, human gates

- **Scope**
  - Confirmed exploits become deterministic regression cases in a versioned, queryable store.
  - Run the full suite when the Orchestrator triggers it. Detect a previously fixed vulnerability reappearing. Flag when
    a fix in one category causes a regression in another.
  - A regression pass must mean the vulnerability is fixed, not that model behavior drifted: repeat runs and assert on
    side effects, not only on wording.
  - Documentation agent: validates required fields and uniqueness before writing a report. Each report has a unique
    ID and severity, description and clinical impact, minimal reproducible sequence, observed versus expected
    behavior, remediation, and status with fix-validation results. Minimum 3 distinct reports.
  - Human approval before publishing critical or high findings and before any remediation. Agents may propose a
    patch and never apply one.
- **Depends on:** P6.
- **Verification**
  - A seeded fix moves a case to fixed, and a reintroduced bug moves it to regressed.
  - A reviewer reproduces one report from its text alone.
  - An injected false positive is caught or held for approval.
- **CI added:** regression suite against a stub target, report-format checks.

### P8. Observability, performance, load

- **Scope**
  - Queryable answers to every PRD observability question: categories tested and case counts; pass/fail by category and
    system version; resilience trend; vulnerability status (open, in progress, resolved); cost per run and its scaling;
    what each agent did, in order. This is also the data the Orchestrator reads.
  - Baseline CPU, memory, latency and throughput profiles for 100 attack cases plus the full regression suite.
  - Load test of 100 consecutive attack cases against the live target, with orchestration latency, LLM latency and
    exploit-storage throughput recorded, the bottleneck named, and the architectural fix documented.
  - Regression scan time-budget SLO, verified in CI. Index documentation for the common query patterns.
- **Depends on:** P6, P7.
- **Verification**
  - Baselines are committed as files.
  - The SLO is asserted in CI against a synthetic database.
  - A mock-target run comes first (as in `loadtest/`). The live 100-case run needs human approval and the cost cap.
  - Cost is attributed per agent.
- **CI added:** the SLO assertion.

### P9. Platform security and CI completion

- **Scope**
  - Remaining gates: coverage floor, mypy baseline, pip-audit, Bandit, self-scan of the platform.
  - Auth model: which agent may call which target with which credential; role-scoped database access.
  - Scheduled and target-change regression triggers, using protected secrets.
  - Handling of harmful generated content (storage and redaction rules).
  - Audit trail so an overnight run can be reconstructed.
- **Depends on:** P2 onward. Most of this should already exist by now; P9 closes the gaps.
- **Verification**
  - A PR that breaks a contract, weakens the suite or adds a secret fails CI.
  - An off-allowlist target is refused and logged.
  - No workflow exposes secrets to forked PRs.
- **CI added:** the remaining gates above.

### P10. Required exercises and evidence

- **Scope**
  - Triage lab: a simulated scan report with at least 10 findings across critical, high, medium and false-positive,
    and for each a documented validate, remediate, defer or document decision.
  - ATO-style evidence packet: architecture and data-flow diagrams, auth model, dependency list with versions,
    vulnerability scan results of the platform itself, eval results, a sample incident postmortem.
  - Integration packet: interface diffs, ADRs for contract corrections, contract-test results from both sides,
    dependency map, end-to-end trace. See the peer versus stub table below.
  - Failure drills: target unreachable, budget exceeded, judge timeout.
  - AI cost analysis: actual development spend and projections at 100, 1K, 10K and 100K runs, with the architectural
    change needed at each scale.
- **Depends on:** P6 to P9.
- **Verification**
  - Triage lists at least 10 findings, each with a disposition.
  - Each failure drill yields its typed error.
  - Cost projections use measured per-run cost, not a flat tokens times n formula.

#### Peer integration versus stub testing

These are different evidence and must be labeled accurately in the submission.

| | Peer integration | Contract conformance with a stub |
|---|---|---|
| What | A peer's independently built agent talks to ours through the published contract only | A consumer or producer written from the schema alone, standing in for a peer |
| Proves | Contract sufficiency across teams; ambiguities found by someone else | Both sides conform to the schema |
| Evidence | Interface diffs, ADRs for contract corrections, both-side test results, cross-agent trace | Contract-test results and a trace |
| Depends on | A peer who exists, agrees, and has a working agent | Nothing external |
| Label in docs | "Peer integration" | "Contract conformance test". Never described as peer integration. |

Whether a peer exists is unknown and is a confirmation item (section 5).

### P11. Final delivery

- **Scope:** demo video (3 to 5 minutes) showing live attacks against the deployed target and key decisions; social post
  tagging @GauntletAI; final README pass; re-check of the deployed URL.
- **Depends on:** everything.
- **Verification:** a line-by-line pass over the PRD submission table with no open item.
- **CI added:** none.

## 5. Deliverables that need applicability confirmation

The PRD lists these but leaves the scope or timing unclear. Each is tracked as an open question in DECISIONS.md.
Until confirmed, plan for the stricter reading and mark the deliverable **(unconfirmed)**.

| Deliverable | Why it needs confirmation | DECISIONS.md |
|---|---|---|
| Peer integration (PRD: "integrates with a peer's independently built agent", "no shared source access") | Depends on whether a peer exists and the cohort runs the integration week. Cannot be satisfied by one person alone. | Q4 |
| "Lab: build one component, inherit another" | Same dependency on a peer's component. | Q4 |
| Demo video at MVP | The PRD table says "one demo video per submission". It is unclear whether MVP needs its own. | Q5 |
| AI cost analysis at MVP | The table lists it without a date. Plan on actual spend at MVP and the full analysis at Final. | Q5 |
| Vulnerability reports (3 minimum) at MVP | The Documentation agent is Final scope in this plan. Confirm whether MVP expects any report. | Q5 |
| Independent code repo | Whether the existing repo plus a separated package counts. | Q1 |
| Stable deployed URL | A rotating quick tunnel may not meet "publicly accessible" with every checkpoint. | Q2 |
| ATO-style evidence packet vs. Architecture Defense "evidence packet" | The PRD uses both terms. They are treated as two artifacts: a draft at Defense, a full packet at Final. | Q6 |
| Queue documentation | Applies only if the platform uses a queue. | Q7 |
| SQL indexing and migrations | Applies only if the exploit store is SQL. | Q7 |
| OWASP items such as SSRF | Applicable only if the target has a relevant surface. Confirm from target code in P1. | Q8 |

## 6. CI ladder

| Checkpoint | Jobs added |
|---|---|
| P0 | Lint, secret scan, markdown and link check |
| P1 | Threat-model category ID check |
| P2 | Contract tests, schema-diff check, migration tests |
| P3 | Suite schema validation, synthetic-data scan, allowlist tests (no live calls) |
| P4 | Judge evaluation on the labeled set with recorded or stub responses |
| P5 | Documentation checks |
| P6 | State-machine tests with scripted agents |
| P7 | Regression suite against a stub target, report-format checks |
| P8 | Regression SLO assertion |
| P9 | Coverage floor, mypy baseline, pip-audit, Bandit, platform self-scan |
| P10, P11 | Evidence-file presence checks |

Rules: live and paid calls never run in CI on pull requests; secrets are available only on protected branches;
the existing `W2 Eval Gate` keeps running unchanged on the target.

## 7. PRD traceability (summary)

| PRD requirement | Checkpoint |
|---|---|
| Stand up target, document changes, deployed URL | P0, every checkpoint |
| Threat model, six categories, OWASP mapping | P1 |
| Versioned contracts, error schemas, contract tests, migration notes | P2 |
| Attack suite, 3+ categories, boundary / invariant / regression tagging | P3 |
| Independent Judge, ground truth, drift detection | P4 |
| Architecture doc, AI-use disclosure, rate limits and auth docs | P5 |
| Orchestrator, queue, cost halting, regression triggers | P6 |
| Regression harness, Documentation agent, human gates, data quality | P7 |
| Observability, baselines, load test, SLO, indexes | P8 |
| Platform security, access control, audit | P9 |
| Triage lab, ATO packet, integration packet, failure drills, cost analysis | P10 |
| Demo video, social post, final pass | P11 |
| Build-versus-configure record | P0 |
| Cost controls, allowlist, synthetic data | Section 2.2, before the first live run |

