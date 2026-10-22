# P-U: possible post-dispatch undercount

status: open

Recorded 2026-10-21 by the R7-R8 offline Build. It stays `open` until a separate, reviewed safety-code cycle closes it and you
approve the closure. Build does not fix it.

## Rule

No billable live campaign may start while this record is open. That means no run that reserves a target chat above $0 and no
provider model call, so R9 to R14. R7 and R8 are $0 and are not blocked by it. `live_campaign.py` billable cases are not run
against any public target. `scripts/preflight_live.py` returns NO-GO for `p_u_closed` until this file reads `status: closed`
and also carries the three fields `closing_test`, `closing_commit` and `approved_by`.

## Findings (characterized by `tests/test_r7_accounting.py`, offline, no flag changed)

1. Reproduced. `SessionClient.post_chat` with a client ledger (the `live_campaign.py` path) releases the ledger reservation at $0 when
   the transport fails after the request was dispatched. The chat POST did leave the process, the outcome is unknown, and
   `committed_usd` then shows $0. Test: `test_p_u_post_dispatch_transport_failure_releases_the_ledger_at_zero`.
2. The journal path is correct. The same failure leaves the row `reserved` as `unknown`, counted in full, and never replayed.
   Test: `test_journal_path_holds_the_reservation_on_the_same_failure`.
3. New in this Build. The judge's provider path has the same shape. A timeout or a transport error after the request was handed to
   the provider transport releases the judge reservation at $0. Test:
   `test_f6_provider_failure_after_dispatch_releases_the_judge_reservation_at_zero`. Closure of P-U must cover this path as well.
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

Only in a separate reviewed safety-code cycle. Either make a post-dispatch failure leave the row `reserved` (still counted), settled
only on evidence, on both paths in findings 1 and 3, with a regression test. Or prohibit the client-ledger path for billable use. You
review and approve the closure. Then this file changes to `status: closed` with `closing_test`, `closing_commit` and `approved_by`,
and the characterization tests above change deliberately in the same cycle.
