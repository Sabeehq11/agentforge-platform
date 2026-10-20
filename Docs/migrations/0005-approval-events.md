# 0005 Approval events and regression jobs

- Date: 2026-10-20
- Schema: platform store. New tables `approval_events`, `regression_jobs`, `content_rejections`.
- Version change: store 0004 to 0005. Contracts stay v1.
- Breaking: no. `exploits`, `reports`, `version_handoffs` and `run_logs` are not altered.
- What existing rows become: nothing. The new tables start empty. A later handoff inserts its job in the same transaction.
- How to reverse: drop `content_rejections`, `regression_jobs` and `approval_events`. Do not drop earlier tables.

`approved_by` is a label from the operator approval file. It is not an authenticated principal. There is no identity provider, session, or proof that the named person is present. A missing, blank, stale, or wrong-purpose record is refused. A well-formed label is stored as written.

`regression_jobs` is one SQLite table for one worker. It is not the message queue rejected in ADR-003. Depth is `pending` plus `claimed`. The worker claims the oldest pending row. Newer jobs wait. They are not dropped and they are not claimed in parallel. A job row is inserted in the same transaction as its handoff, and its status changes in the same transaction as the handoff status.

`content_rejections` stores a fixed reason and the journal `call_id` it belongs to. A rejection for another call does not satisfy this one. It does not store a model body, a transcript, or a credential.
