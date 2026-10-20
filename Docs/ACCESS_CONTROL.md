# Access control for platform data (design)

Design record for checkpoint P2. P9 enforces the role split in code. SQLite has one writer
and no database users, so roles are code paths, as [ADR-005](adr/005-state-store.md) records.

A Python `Grant` is an in-process capability issued by `CampaignLoop` or the regression suite. A non-blank
`approved_by` in the approval file is a label the operator wrote. Neither is an authenticated principal. There is
no identity provider, session, or proof that the named person is present. A missing, blank, stale, or wrong-purpose
record is refused. A well-formed label is stored as written.

## Who may start a run

The operator process on the machine that holds the store is the boundary. `scripts/orchestrate.py` starts a dry
run. A live run stays refused while `LIVE_ENABLED` is false. `scripts/regress.py` starts a stub regression against
`data/agentforge.db`. Agent packages cannot open a campaign, observe a version, or claim a job. The scheduled
workflow has no store and no secrets, so it does not start either.

## Who may view a report

The operator who can read the store can read a report body. That is filesystem access, not a login. Observability
queries and `reconstruct()` return status, ids, and `sequence_hash` only. Agent modules have no list-all-reports
reader. The Documentation agent receives only the exploit it is drafting. Draft files in `reports/` are fixture
drafts, not a publication channel.

## Regression job backlog

`regression_jobs` is one SQLite table and one worker. It is not the message queue rejected in ADR-003. Depth is
`pending` plus `claimed`. The worker claims the oldest pending row. Newer jobs wait. They are not dropped and they
are not claimed in parallel. A crash inside an open transaction leaves both the handoff and the job at the old
status. A committed repeat is not replayed.

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
