# Live 100-case load test (D-13)

Measured. The evidence is [evals/results/d13-load.json](../evals/results/d13-load.json). It is not
[evals/results/baseline-p8.json](../evals/results/baseline-p8.json). That baseline is an offline `CampaignLoop`
profile with `satisfies_d13` false and LLM latency `not_measured`. An offline fake-transport run does not satisfy
D-13. `scripts/loadtest.py` refuses while `LIVE_ENABLED` is false and does not open a socket.

The PRD asks for 100 consecutive attack cases against the live target, with orchestration latency, LLM latency and
exploit-storage throughput, the bottleneck named, and the architectural change documented. This run is that test on
the deployed target's Week 1 stub route. It is not a real-provider benchmark. `PROVIDER_ENABLED` stayed false, and
the report records `zero_cost_stub: true`.

The stored `satisfies_d13` field is the harness's own flag. It does not mean the PRD's D-13 is met: D-13 is `partial` in
[PRD_TRACEABILITY.md](PRD_TRACEABILITY.md). This is a stub-route measurement. The live-target half, a run with a
non-fake transport and `zero_cost_stub: false`, is owned by R13 and has not run.

## Measured result

Quoted from `evals/results/d13-load.json`. Nothing here is recomputed.

- 100 of 100 cases completed. `stopped_by` is null. `live` is true. `satisfies_d13` is true.
- Orchestration latency: 90.13541795802303 seconds.
- Stub LLM latency: 0.0 seconds across 100 samples, labeled `target_stub_llm`. Zero is a measured sample. It is not a missing sample and it is not a provider-model latency.
- Exploit storage: 100 rows in 0.016690212418325245 seconds, 5991.5354876013225 rows per second.
- Bottleneck named by the harness: `orchestration`.

The harness already keeps one authenticated session. Login and patient open happen once, then the 100 chats are sent. The `architectural_fix` sentence for this bottleneck states that existing behavior and names the unbuilt target-side change. It does not address the span that dominated this run. The stored `d13-load.json` was written before that wording changed and is not rewritten.

## Bottleneck

The agent's gateway allows 60 verified chats per user per rolling minute and does not retry. OpenEMR wraps a non-200 agent response, including 429, as 502. The harness stays at 59 chats in any 60-second window and waits until the oldest chat ages out. It does not raise the agent limit and does not retry.

That wait is inside the orchestration span. Storage took about 0.017 seconds. The stub model reported 0.0 seconds. The remaining orchestration time is the authenticated chat path plus the one window wait required to send all 100 chats without a 429. A failed response is not counted as completed.

## Architectural change

Pace verified chats to the agent's published rolling window, as this run did, and treat that wait as part of orchestration latency. Do not raise the agent's 60-per-minute limit and do not retry a 429. A later change that would shorten this span is a reviewed target-side limiter that can admit a bounded 100-chat measurement without converting the 61st chat into a 502. That change is not made here. It is not a provider-model optimization: this run did not call a provider model.

## What this run does not close

- It does not measure a billable target model or a provider model. Measured stub spend for these 100 chats is `$0`. The `$0.05` figure remains a reservation assumption for a billable chat, not a measured bill.
- E-6 stays open. No provider call was in this path, so no provider-limit attestation was required for this run.
- E-3 and S-1 are not re-closed by this file. The harness checked identity, the pin, and the authenticated stub guard before chat. Those checks are not a new attestation.
- `LIVE_ENABLED` is a reviewed source constant. It is false in committed code after the run. An environment variable cannot set it.
