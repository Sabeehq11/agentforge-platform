# Live 100-case load test (D-13)

Not run. A mock baseline is not this test.

The PRD asks for 100 consecutive attack cases against the live target, with orchestration latency, LLM latency and
exploit-storage throughput, the bottleneck named, and the architectural fix documented. None of that was measured.
`evals/results/baseline-p8.json` is an offline `CampaignLoop` profile. It sets `satisfies_d13` to false and records
LLM latency as `not_measured`.

## Why it is blocked

- `LIVE_ENABLED` and `PROVIDER_ENABLED` are source constants. An environment variable cannot set them.
- The allowlist is empty for a public host. E-3 (identity check) and S-1 (running stack equals the pin) are open.
- E-6 (provider spending limit) is not attested.
- `max_attacks_per_run` is 20. The shared ceiling is $5. About $0.05 per target chat already spends $5 across 100
  chats, before model cost. Committed spend is $0.1022. `config/orchestrator.yaml` can only tighten those caps.

## Unblock conditions

All of these are required. This file does not perform any of them.

1. Operator approval that names the exact cap, the case count (100) and the target pin.
2. A reviewed source change to `LIVE_ENABLED`. An env flag must remain ignored.
3. A reviewed allowlist edit, an identity check (E-3), a running stack equal to the pin (S-1), and a provider-limit
   attestation (E-6) if any model call is in the path.
4. A budget change that can cover 100 target chats plus model calls. That change is not made from
   `config/orchestrator.yaml`.
5. A `RateCap` sized so the run halts rather than bypassing it. The PHI scan still runs before any stored transcript.
   The kill switch still halts before the next call.

When those are met, the run records orchestration latency, LLM latency and exploit-storage throughput, names one
bottleneck, and documents the architectural fix in `ARCHITECTURE.md`. Until then D-13 stays not started.
