# Build versus configure record

Required by the Week 3 PRD before any agent role is implemented, and an Architecture Defense deliverable.

**Evidence status.** The tool descriptions below come from general knowledge and have **not** been checked against
each tool's own documentation. Every claim about a tool is marked **(unverified)**. A later approved step checks
them. The conclusions are design intent, not measured results.

## What we need

| Role | Job |
|---|---|
| Red Team | Generate novel attacks, mutate partial successes, run multi-turn sequences against the Co-Pilot |
| Judge | Decide whether an attack succeeded, a defense held, or a regression appeared, independently of the attacker |
| Orchestrator | Read coverage gaps, open findings and regressions, then choose the next campaign |
| Documentation | Turn a confirmed exploit into a reproducible report after validating required fields and uniqueness |
| Deterministic layer | Replay, canary and PHI checks, boundary and fuzz inputs, regression store |

The target is an LLM application behind a session-authenticated web module (ADR-002). The attack content is mostly
natural language and uploaded documents, and the verdict depends on clinical-data semantics (cross-patient exposure,
PHI, unsupported claims).

## Tools evaluated

| Tool | What it covers (unverified) | Where it falls short here (unverified) | Use |
|---|---|---|---|
| Burp Suite | Web proxy, scanner and manual testing for HTTP apps, including session and CSRF handling | Not LLM-aware. No notion of cross-patient leakage or model refusal. Scripting an agent loop is awkward. Commercial licence for automation | Optional manual aid. Not a platform component |
| OWASP ZAP | Open-source web scanner, spider and active scan, scriptable, runs headless in CI | Same limits as Burp: generic web findings (headers, injection, access control), not model behavior. The Co-Pilot's risk sits in what the model says, not in transport flaws | Candidate to run once against the OpenEMR module for the web Top 10 items (P3 or later). Configure, do not build |
| Semgrep | Static analysis of source code with rules | Needs source. Our boundary is HTTP only (ADR-001), so it cannot scan the target. It can scan this platform | Use on this platform's own code in P9 |
| Garak | Open-source LLM vulnerability scanner with probes and detectors for prompt injection, leakage and similar | Aimed at model endpoints with its own generators. Our target is a stateful app behind a login with patient context, so probes need an adapter. Detectors do not know our PHI and patient boundaries | Candidate source of seed probes and ideas. Adapter effort to be assessed in P3 or P4 |
| promptfoo | Open-source LLM eval and red-team harness with config-driven test cases and graders | Same adapter and session problem. Graders are LLM-based by default, which conflicts with Judge independence unless configured carefully | Candidate for case format ideas. Not adopted |
| PyRIT | Microsoft's open-source framework for LLM red teaming with orchestrators and scorers | Python library and not a service. Brings its own abstractions, which conflicts with ADR-003 (small own state machine). Fit for multi-turn attack is plausible but unproven here | Candidate library for the Red Team role. Evaluate in P4 |
| Commercial red-team platforms | Hosted attack libraries and reporting | Send transcripts to a third party, cost is unknown, and healthcare data and trust boundaries need review. Not evaluated | Not adopted. Revisit only with a written data-handling review |
| Plain deterministic tooling (replay, canary strings, regex PHI checks, boundary and fuzz inputs, a SQL store) | Exact, repeatable, free, auditable | Cannot invent new attack ideas or judge ambiguous semantics | Adopt as the first layer for the Judge, the executor and the regression harness |

## Decision per role

| Role | Decision | Justification |
|---|---|---|
| Red Team | Build custom, may wrap PyRIT or Garak ideas | Needs multi-turn, patient-context-aware, budget-capped mutation of partial successes against a session-authenticated target. No evaluated tool does this out of the box (unverified). Model choice is open (ADR-004) |
| Judge | Build custom, deterministic rules first, then an LLM only for ambiguous cases | Verdicts depend on our own invariants (patient IDs, canaries, PHI patterns, tool allowlist). Must be independent of the Red Team and verifiable against a labeled set. A generic grader would not carry our criteria |
| Orchestrator | Build custom | It reads our own coverage and findings data and enforces our cost caps. Mostly deterministic rules, with at most light AI help |
| Documentation | Build custom | Output format and validation rules are set by the PRD and our data model. A template plus validation is mostly deterministic, with an LLM for prose only |
| Deterministic layer | Build, small | Replay, canary, PHI and boundary checks are small and must be exact. Reuse standard libraries |
| Web Top 10 scanning | Configure (ZAP) | Generic web checks are a solved problem. Custom code is not justified. Use results as evidence for Top 10 mapping, scoped by the allowlist |

## Open items

- Verify each tool claim against its own documentation in a separate approved step.
- Any tool that sends traffic to the target must go through the allowlist chokepoint or be wrapped by it. A tool
  that cannot be constrained that way is not adopted.
- Licensing and cost of Burp Suite and any commercial platform are unchecked.
