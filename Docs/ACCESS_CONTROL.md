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
`rejected`. Critical and high findings require a `publish_finding` approval before anyone outside the platform
sees them. Medium and low still require that human `decide` step, and an agent still cannot insert them as
`published`. The PRD names the approval-record requirement for critical and high only, so a medium or low
`decide("published")` does not look up a `publish_finding` file. That is the publication policy, not a skip of
the human gate. Remediation is a second gate: an agent may set `remediation_status` to `proposed` only, and
`authorized` requires a separate `authorize_remediation` record bound to the report id and the proposal hash.
A publication approval does not authorize remediation, and a remediation approval does not publish. Neither
record applies a patch. The code that checks the human identity is P9. P7 enforces that no agent can skip either
gate.
