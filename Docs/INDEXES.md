# Index documentation

P8. The indexes on severity, attack category and system version already exist in
[src/agentforge/store/schema.sql](../src/agentforge/store/schema.sql). This file records which query uses which index.
`EXPLAIN QUERY PLAN` is proof the planner uses the index. It is not the regression-scan time budget. That budget is
`config/slo.yaml`, measured by one `run_suite` call and labeled `stub_regression_suite`. No schema change was required,
so there is no migration 0005.

| Query | SQL | Index |
|---|---|---|
| By severity | `SELECT id, severity FROM exploits WHERE severity = ?` | `idx_exploits_severity` |
| By category | `SELECT id, category FROM exploits WHERE category = ?` | `idx_exploits_category` |
| By system version | `SELECT id, system_version FROM exploits WHERE system_version = ?` | `idx_exploits_system_version` |

`tests/test_p8_slo.py` runs `EXPLAIN QUERY PLAN` on a synthetic database and fails if the plan is `SCAN exploits`
with no index name. The suite scan itself reads `regression_cases` by primary key order (`ORDER BY id`) and joins
`regression_runs` on `idx_regression_runs_case_version`. That scan's time budget is the SLO, not this table.
