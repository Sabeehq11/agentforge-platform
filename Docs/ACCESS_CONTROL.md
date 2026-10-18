# Access control for platform data (design)

Design record for checkpoint P2. It is not enforcement. P9 enforces the role split in code. SQLite has one writer
and no database users, so roles are code paths, as [ADR-005](adr/005-state-store.md) records.

## Who writes

| Data | Who may write | What they may not do |
|---|---|---|
| Exploit, status `draft` | Judge | Set status to `published` |
| Exploit draft fields | Documentation | Publish, or insert an exploit the Judge did not confirm |
| Regression case | Harness, from a Judge verdict | Invent a case that has no exploit row |
| Run log | The agent whose role the row names | Write another role's row |
| Coverage metric | Harness | None in P2. The reader is the Orchestrator, in P6 |

No agent writes status `published`. The insert path refuses it.

## Who reads

The Orchestrator and the harness read exploits, regression cases and coverage. The Documentation agent reads the
exploit it was given and nothing else. A human reads everything.

## What approval precedes publication

A human moves an exploit from `draft` to `pending_approval`, reviews it, and moves it to `published` or
`rejected`. Critical and high findings require that approval before anyone outside the platform sees them. An
agent may propose a remediation and never apply one. That rule is stated here and in the Architecture Defense
packet. The code that checks the human identity is P9.
