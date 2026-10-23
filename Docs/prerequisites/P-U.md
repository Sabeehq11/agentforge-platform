# P-U: possible post-dispatch undercount

status: closed
closing_commit: 12450ce660c494578556816521111f0d94fa07db
closing_test: tests/test_r7_accounting.py::test_p_u_post_dispatch_transport_failure_holds_the_ledger_reservation tests/test_r7_accounting.py::test_f6_provider_failure_after_dispatch_holds_the_judge_reservation
approved_by: Sabeeh Qureshi

Recorded 2026-10-21 by the R7-R8 offline Build. It stays `open` until a separate, reviewed safety-code cycle closes it and you
approve the closure. Build does not fix it.

## Rule

No billable live campaign may start while this record is open. That means no run that reserves a target chat above $0 and no
provider model call, so R9 to R14. R7 and R8 are $0 and are not blocked by it. `live_campaign.py` billable cases are not run
against any public target. `scripts/preflight_live.py` returns NO-GO for `p_u_closed` until this file reads `status: closed`
and also carries the three fields `closing_test`, `closing_commit` and `approved_by`.

## Findings (characterized by `tests/test_r7_accounting.py`, offline, no flag changed)

1. Closed. `SessionClient.post_chat` with a client ledger keeps the reservation when the transport fails after the request was
   dispatched. The chat POST did leave the process and the outcome is unknown, so the row stays `reserved` and counts in full.
   Test: `test_p_u_post_dispatch_transport_failure_holds_the_ledger_reservation`.
2. The journal path is correct. The same failure leaves the row `reserved` as `unknown`, counted in full, and never replayed.
   Test: `test_journal_path_holds_the_reservation_on_the_same_failure`.
3. Closed. A Judge timeout or transport error after the request was handed to the provider is `ProviderOutcomeUnknown`. That path
   holds the reservation. A local stub timeout never leaves the process and is still released. Test:
   `test_f6_provider_failure_after_dispatch_holds_the_judge_reservation`.
4. The chokepoint reserves `Budget` before the spend-limit and rate gates and does not return it when those gates refuse. Budget
   overcounts, which is conservative. This does not belong to P-U and is not a defect that can allow overspend.
5. With a client ledger, a chat reserve counts twice in `Budget` (once by the ledger, once at the chokepoint). `sequence.py`
   preflight already encodes it as `2 * need`.
6. `per_day_usd` is never reset, so it is a second lifetime cap, not a daily one. A new process re-seeds both counters from the
   ledger's committed total.

## Why it matters

If a post-dispatch failure billed, the ledger understates exposure by up to the reservation, and by any excess above it. The
$12.00 lifetime ceiling is defined as `I + O + X`. The ledger cannot hold X. Releasing at $0 on an unknown outcome hides spend
from both `O` and `I`.

## Closure

Closed 2026-10-22 by Sabeeh Qureshi. Findings 1 and 3 now leave the row `reserved` until there is evidence, and the characterization
tests were changed in the same cycle. The client-ledger hold is `12450ce660c494578556816521111f0d94fa07db`. The Judge provider hold
was already in `6d2446205cd23c903b375b8b49a6e3ac14064fde`; that commit is not this closure. Known non-bills are still released.
