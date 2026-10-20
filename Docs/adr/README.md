# Architecture decision records

Rules (from [DECISIONS.md](../DECISIONS.md)): an ADR is never edited after it is accepted. A change is a new ADR
that supersedes the old one. Every ADR must list at least two rejected alternatives with the reason for each
(`scripts/check_adrs.py` enforces this in CI).

| ADR | Title | Status | Open question |
|---|---|---|---|
| [001](001-repo-strategy.md) | Repo strategy: independent repo, target pinned by SHA, HTTP only | accepted | Q1 |
| [002](002-target-access.md) | Target access: public OpenEMR module as a synthetic identity | accepted | A-004 |
| [003](003-coordination.md) | Coordination: small persisted state machine | accepted | Q9 |
| [004](004-models-per-role.md) | Models: per-role configuration, distinct families for Red Team and Judge | accepted | Q10 |
| [005](005-state-store.md) | State store: SQLite | accepted | Q12 |
| [006](006-observability.md) | Observability: own SQLite traces | accepted | Q11 |
| [007](007-url-handling.md) | Target URL: quick tunnel with reviewed manual edits | accepted (provisional) | Q2 |
| [008](008-dispatch-journal.md) | Dispatch journal, rate-limit handling and cost stop | accepted | Q9 |
| [009](009-regression-harness.md) | Regression harness: stub suite, append-only runs, separate remediation gate | accepted | Q5, Q7 |

Template: [TEMPLATE.md](TEMPLATE.md).
