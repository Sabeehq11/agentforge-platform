# Public-target authorization (prerequisite for Gate K1)

status: closed
implemented_commit: 6d2446205cd23c903b375b8b49a6e3ac14064fde
approved_by: Sabeeh Qureshi
closing_test: tests/test_chokepoint.py::test_a_zero_cost_public_request_needs_an_origin_bound_approval

Recorded 2026-10-21 by the R7-R8 offline Build. Gate K1 (a temporary `LIVE_ENABLED` change) is UNAVAILABLE in R7 and R8 until this
file reads `status: closed` with `implemented_commit` and `approved_by`, and `scripts/preflight_live.py` reports `k1_available` GO.

## Why

`chokepoint.request()` consults `authorize_spend` only when the cost estimate is above $0. A zero-cost GET to a public host is
therefore gated only by the kill switch, the allowlist and the budget token. A public request would run with no public-target
authorization at all.

## Needed, in its own reviewed safety-code cycle

- A `public-target` approval scope in `operator_approval.py`, with a 24-hour age cap.
- An origin binding, applied to zero-cost requests too.
- Tests, and your approval of the implementation.

Until then R7 identity is operator-observed, E-3 stays partial, and the earliest platform-made public request is R9 under R9's own
approval. K1 would then be a fresh request, never bundled with another gate.
