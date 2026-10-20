# 0004 Regression lifecycle

- Date: 2026-10-19
- Schema: platform store. Additive columns on `regression_cases`. New tables `regression_runs`, `reports`, `regression_detections`.
- Version change: store 0003 to 0004. Contracts stay v1.
- Breaking: no. `exploits`, `run_logs`, `coverage_metrics`, `campaigns` and `dispatch_journal` are not altered.
- What existing rows become: a `regression_cases` row, if any, gains `lifecycle` `open`, `invariant_id` `unregistered` and an empty `subcategory`. No P6 code writes that table, so a migrated database has no such rows.
- How to reverse: drop `regression_detections`, `reports` and `regression_runs`, drop `idx_regression_cases_exploit`, then rebuild `regression_cases` without the three new columns. Do not drop earlier tables.

`regression_runs` is append-only. One row is one completed repeat for one case and one target pin. A later pin does not update an earlier row. `regression_cases.lifecycle` is a cache of the latest completed pin, not history.

`reports.status` is publication. `reports.remediation_status` is a separate gate. A publication approval does not authorize remediation, and neither applies a patch. `fix_validation` is updated from `regression_runs` and does not change publication status.

`regression_detections` stores one `regression_detected` detail per target pin and case so a resumed claim cannot emit a second envelope.

No new v1 message. The version handoff row remains the trigger. `regression_detected` remains the result.
