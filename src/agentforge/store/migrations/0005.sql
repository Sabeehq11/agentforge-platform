-- P9 approval labels and regression jobs. Additive. No v1 contract change.
-- approved_by is a label the operator wrote. It is not an authenticated principal.
-- regression_jobs is one SQLite table and one worker. It is not the queue ADR-003 rejected.

CREATE TABLE approval_events (
    id INTEGER PRIMARY KEY,
    report_id TEXT NOT NULL CHECK (length(report_id) > 0),
    purpose TEXT NOT NULL CHECK (purpose IN ('publish_finding', 'authorize_remediation')),
    approved_by TEXT NOT NULL CHECK (length(approved_by) > 0),
    bound TEXT NOT NULL CHECK (length(bound) > 0),
    decision TEXT NOT NULL CHECK (length(decision) > 0),
    recorded_at TEXT NOT NULL
);

CREATE INDEX idx_approval_events_report ON approval_events (report_id, purpose);

CREATE TABLE regression_jobs (
    id INTEGER PRIMARY KEY,
    handoff_id INTEGER NOT NULL UNIQUE REFERENCES version_handoffs (id),
    status TEXT NOT NULL CHECK (status IN ('pending', 'claimed', 'done')),
    claimed_by TEXT,
    recorded_at TEXT NOT NULL
);

CREATE INDEX idx_regression_jobs_status ON regression_jobs (status, id);

CREATE TABLE content_rejections (
    id INTEGER PRIMARY KEY,
    correlation_id TEXT NOT NULL CHECK (length(correlation_id) > 0),
    call_id TEXT NOT NULL CHECK (length(call_id) > 0),
    reason TEXT NOT NULL CHECK (length(reason) > 0),
    recorded_at TEXT NOT NULL
);

CREATE INDEX idx_content_rejections_correlation ON content_rejections (correlation_id);
