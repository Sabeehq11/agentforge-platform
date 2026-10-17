# ADR-003: Coordination: small persisted state machine

- Status: accepted
- Date: 2026-10-17
- Related questions: Q9

## Context

The PRD requires a multi-agent system with durable coordination, resumable state and typed handling of agent
failure. Weeks 1 and 2 used a hand-written, inspectable supervisor graph. The platform's agents (Orchestrator, Red
Team, Judge, Documentation) have distinct trust levels and exchange typed messages.

## Options considered

### Chosen: a small persisted state machine in Python
- Explicit states and transitions stored in SQLite, resumable after a crash, inspectable, and consistent with Week 2.
  No new dependency to audit.

### Rejected: LangGraph
- Heavier dependency and more surface to scan and pin. Gives graph and checkpoint helpers we can write in a few
  hundred lines. Reopen if we need many branching or human-in-the-loop flows that the small machine handles badly.

### Rejected: a message queue (Redis, RabbitMQ, SQS)
- New infrastructure and a service to secure, with no scale need at this volume. The PRD makes queue documentation
  conditional. Reopen if concurrent regression runs or multiple workers cause contention on SQLite.

### Rejected: CrewAI or AutoGen
- Conversation-style frameworks that blur the typed message boundaries and trust levels the PRD wants explicit.

## Decision

A persisted state machine with explicit states and transitions stored in SQLite, designed in P2 and built in P6.

## Consequences and risks

- We own the correctness of resume and typed-error behavior, so P6 needs tests with scripted agents.
- No framework tracing for free. See ADR-006.

## Verification that the decision holds

- P6: a killed agent mid-run yields a typed error and a resumable state; end-to-end trace under one correlation ID.
