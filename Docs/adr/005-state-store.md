# ADR-005: State store: SQLite

- Status: accepted
- Date: 2026-10-17
- Related questions: Q12, Q7

## Context

The platform stores exploit records, regression cases, agent run logs and coverage metrics. The PRD requires data
quality constraints, migrations, indexes, and a regression-scan time budget verified in CI. The Week 2 target already
uses SQLite for traces, so the tooling is familiar.

## Options considered

### Chosen: SQLite
- No new infrastructure, a single file, works in CI with a synthetic database, supports constraints, indexes and
  migrations. Fits one operator and one platform process.

### Rejected: PostgreSQL or another server database
- Adds a service to run, secure and back up, with no scale need now. Reopen if concurrent writers or multiple
  hosts are needed (see ADR-003 reopen triggers).

### Rejected: flat JSON or JSONL files
- No uniqueness or referential constraints, no indexes, and migrations become manual.

## Decision

SQLite for platform state. Schema, migration tool and access roles are designed in P2.

## Consequences and risks

- Single writer. Role-scoped access is by convention and code paths, not database users. P9 documents the limit.
- Database files are git-ignored and never committed.

## Verification that the decision holds

- P2: duplicate and incomplete exploit inserts rejected; a migration adds a field with no data loss.
- P8: the regression scan SLO is asserted in CI against a synthetic database.
