# ADR-006: Observability: own SQLite traces

- Status: accepted
- Date: 2026-10-17
- Related questions: Q11

## Context

The PRD asks for queryable answers about coverage, pass and fail by version, resilience over time, vulnerability
status, cost per run and per agent, and an ordered record of what each agent did. This data is also what the
Orchestrator reads, so it must be queryable by code, not only by humans.

## Options considered

### Chosen: our own trace tables in SQLite with correlation IDs and per-agent cost
- Same store as ADR-005, so the Orchestrator queries it directly. No third party receives transcripts that may quote
  target output. Matches the Week 2 approach.

### Rejected: Langfuse (hosted or self-hosted) now
- Extra service and a new place where attack transcripts and cost data would live. Deferred, not dismissed. Reopen
  if trace browsing becomes the bottleneck for humans.

### Rejected: LangSmith or Braintrust
- Hosted SaaS that would receive transcripts and needs another key to protect. Ties tracing to a vendor before we
  know what we need.

## Decision

Own SQLite traces. The table design is made in P2. Langfuse is deferred.

## Consequences and risks

- We build the dashboards and queries ourselves.
- Trace content must be scanned for PHI-like patterns before storage (safety envelope, ROADMAP 2.2).

## Verification that the decision holds

- P6: one end-to-end run traced under one correlation ID. P8: each PRD observability question has a query.
