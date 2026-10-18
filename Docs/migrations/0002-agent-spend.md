# 0002 Agent spend

- Date: 2026-10-18
- Schema: platform store, new table `agent_spend`. Message schemas are unchanged. `RecordedTranscript` was added the same day under `contracts/v1/` and is not a table.
- Version change: store 0001 to 0002. Contracts stay v1.
- Breaking: no. Existing exploit, regression, run-log and coverage rows are not rewritten.
- What existing rows become: unchanged. The new table is empty.
- How to reverse: drop `agent_spend`. Do not drop the 0001 tables.

Reserved USD and incurred USD are separate columns. A rejected call is not incurred. Releasing a reservation sets
reserved to 0 and does not write a negative incurred amount. Target-side rows are fixture or operator amounts.
This note does not record a live usage query.
