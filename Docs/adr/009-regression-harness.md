# ADR-009: Regression harness: stub suite, append-only runs, separate remediation gate

- Status: accepted
- Date: 2026-10-19
- Related questions: Q5, Q7

## Context

P6 records a version handoff and does not replay it. The exploit status enum has no `fixed` value. A passing
regression has to mean the category invariant held, not that the wording changed and not that the response was
401. Publication and remediation are different human acts. The Documentation model is still unmeasured.

## Options considered

### Chosen: stub suite, append-only runs, template writer, two approvals
- The suite replays a stored sequence against an in-process stub. Outcomes are inserted and never updated.
  `lifecycle` caches the latest pin. The Documentation agent fills a template and stays off the provider. Publication
  and remediation each need their own operator record. Neither applies a patch.

### Rejected: a last-result column on the case
- A later pin would overwrite the earlier pin. Reappearance could not be queried after the next run.

### Rejected: one approval that both publishes and authorizes remediation
- The PRD separates publishing a finding from applying or authorizing a fix. One record would let a publication
  approval stand in for remediation.

### Rejected: a live replay in P7
- No public URL, an empty allowlist, and no provider attestation. A live chat also spends the shared ceiling.
  The stub rule that re-executes an uncommitted repeat must not be copied onto a live call.

## Decision

P7 runs the regression suite on a stub, stores every completed repeat, and keeps publication and remediation as
separate gates. Live replay stays blocked.

## Consequences and risks

- A stub pass is not evidence against the deployed target. Architecture and progress must say so.
- An unregistered category cannot become fixed. That is intentional, not a missing 401 rule.

## Verification that the decision holds

- `tests/test_p7_invariants.py`, `tests/test_p7_suite.py`, `tests/test_p7_lifecycle.py` and `tests/test_p7_gates.py`.
  `scripts/check_schema_diff.py` reports no breaking v1 change.
