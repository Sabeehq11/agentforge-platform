# AI cost analysis

Actual development spend is the local ledger `data/agentforge.sqlite3`, table `agent_spend`, read only. The committed spend log in [PROGRESS.md](PROGRESS.md) is the rounded record of that same sum. `scripts/check_cost.py` compares [cost/unit-costs.json](cost/unit-costs.json) to the ledger and exits 1 on a call-id, state, or amount mismatch. It does not write a ledger row.

Three amounts are kept apart. They are not blended into one per-run dollar.

- `ledger_usd` is the amount the ledger recorded, in the state the ledger recorded.
- `provider_charge_usd` is a verified provider bill. It is null when no per-call provider bill was stored.
- The `$0.05` projection unit is a reservation assumption. It is not a measured target bill.

D-13 was measured on the Week 1 stub route. [evals/results/d13-load.json](../evals/results/d13-load.json) records `zero_cost_stub: true` and 100 of 100 chats. Measured stub spend for that run is `$0`. It is not a ledger row, it is not a verified provider charge, and it is not the `$0.05` reservation. This is not a real-provider benchmark.

## Reconciliation

Every ledger row is one object, including zero-cost incurred rows and released rows. A call id appears once. No historical row is rewritten.

- Ledger `incurred` sums to `$0.1022038`. The spend log rounds that to `$0.1022`. The rounded total is not added on top of the rows.
- Two target rows, `target-chat-5` and `target-chat-685a5e0c6be2`, are `incurred` at `$0.05` each. That `$0.1000` is a reservation written into the incurred column. The target's bill is not independently attested, so `provider_charge_usd` is null. It is not counted again as reserved.
- Verified provider charges sum to `$0.0019128`: `diag-judge-112a52e0c6ee` `$0.000975`, `probe-judge-c7e70e4a93b1` `$0.000291`, `probe-judge-41f064d9f8a3` `$0.000291`, `probe-red_team-b4816368425d` `$0.0000228`, and `judge-9adefda49ebf` `$0.000333`.
- `probe-judge-a6b9e5ffc3f3` is ledger `incurred` at `$0.000291` and inferred once. `Ledger.settle_orphan` wrote that amount from the other calls with the same request. No per-call provider cost was stored, so it is not a verified charge and it is not in the projection unit.
- `$0.0019128 + $0.000291 + $0.1000 = $0.1022038`. Each row is in one of those three sums.

Released rows at `$0` (`probe-judge-dfc0d15b53f2`, `probe-judge-827472582cd8`, `judge-90c1a7a39e1a`, `probe-judge-d9b846c62b60`) and two zero-cost incurred red-team rows are in the file so a missing call id fails the checker. They add nothing.

## Projection output

Quoted from `scripts/check_cost.py`. Target figures are reservation-based. Provider figures are verified samples. The inferred orphan is excluded, which is not a second subtraction.

```json
{"basis": "reservation-based target; verified provider samples kept separate; inferred orphan excluded", "scales": {"100": {"reservation_based_target_usd": 5.0, "verified_provider_sample_usd": 0.03138}, "1000": {"reservation_based_target_usd": 50.0, "verified_provider_sample_usd": 0.3138}, "10000": {"reservation_based_target_usd": 500.0, "verified_provider_sample_usd": 3.138}, "100000": {"reservation_based_target_usd": 5000.0, "verified_provider_sample_usd": 31.38}}}
```

## Shapes

- Reservation-based target chat only: `$0.05` per chat. Not measured target spend. This is the shape for a case the deterministic Judge grades with no model call.
- Reservation-based target chat plus verified provider samples: `$0.05` reservation plus `$0.0000228` plus `$0.000291`. The target term stays reservation-based. One sample is not a rate. The inferred orphan is not a unit cost.

## Architectural change at each scale

- 100 reservation-based target chats are `$5.00` reserved. That meets the shared ceiling before provider samples and before the `$0.1022038` already committed. The change for a billable run is a reviewed budget increase. It is not made here. The measured D-13 stub run spent `$0` and does not remove H-1, E-3, E-6, or S-1. This `$5.00` is not measured target cost.
- 1K: `max_attacks_per_run` is 100, so this is not one run. The change already in the architecture is many capped sequential campaigns. ADR-003 and ADR-005 name SQLite write contention as the reopen condition. The measured D-13 bottleneck was the agent's 60-chat rolling minute, not SQLite. That limiter still applies at this scale. Pacing stays inside the published window. The limiter is not raised here.
- 10K and 100K: the same single-process SQLite limit and the target's in-memory rate limiter, as [ARCHITECTURE.md](../ARCHITECTURE.md) section H already states. No new database. No queue.
