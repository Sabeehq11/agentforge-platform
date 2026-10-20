# ADR-008: Dispatch journal, rate-limit handling and cost stop

- Status: accepted
- Date: 2026-10-19
- Related questions: Q9

## Context

P6 runs Orchestrator, Red Team, executor and Judge under one correlation ID. A crash between reserving spend and
recording the outcome must not replay a call that may have reached the target, and must not bill it twice. A 429 or
503 has to keep its status and Retry-After without a new error code. Spend with no validated signal has to stop.

## Options considered

### Chosen: a write-ahead dispatch journal in the existing SQLite store
- One row per external effect, committed before the effect, with deterministic call ids. Resume rules depend on the
  state found after a crash. Status and Retry-After live in the journal, so the v1 error envelope stays closed.

### Rejected: replay every unfinished call on resume
- A call marked sent may already have reached the target or the provider. Replaying it can double-bill and repeat an
  attack. Reopen only if the target offers an idempotency key this client can set.

### Rejected: a new error code for rate limits
- The v1 envelope is a closed enum of five codes. Adding a code is a breaking contract change. The status and
  Retry-After are already on the HTTP response and fit in the journal.

## Decision

Every external effect is journaled write-ahead. An unknown outcome is never replayed and its reservation is held.
Only an explicit operator accept settles it, through the existing orphan settlement, never a second reservation.
Retries are bounded to 429 and 503. A campaign with no validated signal redirects once, then halts.

## Consequences and risks

- Resume correctness is ours to test. A kill at each journal point has a scripted test.
- The held reservation counts against the shared ceiling until the operator accepts it. That is intentional.

## Verification that the decision holds

- `tests/test_p6_journal.py`, `tests/test_p6_ratelimit.py` and `tests/test_p6_cost.py` cover the crash points, the
  retry bounds and the stop. `scripts/check_schema_diff.py` reports no breaking v1 change.
