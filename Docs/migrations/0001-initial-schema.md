# 0001 Initial schema

- Date: 2026-10-17
- Schema: platform store (`exploits`, `regression_cases`, `run_logs`, `coverage_metrics`, `schema_migrations`)
- Version change: none to v1. This is the first schema.
- Breaking: no. No existing records.
- What existing rows become: nothing. The database is empty when this runs.
- How to reverse: drop the database file. It is git-ignored and holds no committed data.

Adds the unique sequence hash, the required-field checks, and indexes on severity, attack category and system
version. The regression-scan time budget that uses those indexes is P8 and is not part of this note.
