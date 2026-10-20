# 0003 Orchestrator state

- Date: 2026-10-19
- Schema: platform store, new tables `campaigns`, `dispatch_journal`, `signals`, `version_baselines`, `version_handoffs`, `attack_variants`. Message schemas are unchanged.
- Version change: store 0002 to 0003. Contracts stay v1.
- Breaking: no. `run_logs`, `coverage_metrics`, `exploits`, `regression_cases` and `agent_spend` are not altered or rewritten.
- What existing rows become: unchanged. The new tables are empty.
- How to reverse: drop the six new tables in reverse dependency order (`attack_variants`, `signals`, `dispatch_journal`, `campaigns`, `version_handoffs`, `version_baselines`). Do not drop earlier tables.

`dispatch_journal` is the write-ahead record for every external effect (model call, target call, judge-model call).
It stores hashes, statuses, the HTTP status and a parsed `Retry-After`. It never stores a request body, cookie or credential.
A `sent` or `unknown` row is never replayed on resume.

`run_logs` keeps its fixed CHECKs. It has no `executor` role, so the executor step is logged there with role
`harness`, the existing value for the component that records results. `dispatch_journal.role` carries the true role
`executor`. No new error code is added. The rate-limit status and `Retry-After` live in the journal, not in the envelope.

`version_baselines` holds the first verified target pin. `version_handoffs` holds later verified changes with status
`pending`. P7 owns claiming and replaying them. P6 never replays.
