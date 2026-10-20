-- P7 regression lifecycle. New tables and additive columns. exploits, run_logs and the v1 contracts are untouched.
-- regression_runs is append-only. lifecycle on regression_cases is a cache of the latest completed pin, not history.

ALTER TABLE regression_cases ADD COLUMN lifecycle TEXT NOT NULL DEFAULT 'open'
    CHECK (lifecycle IN ('open', 'fixed', 'regressed'));
ALTER TABLE regression_cases ADD COLUMN invariant_id TEXT NOT NULL DEFAULT 'unregistered';
ALTER TABLE regression_cases ADD COLUMN subcategory TEXT NOT NULL DEFAULT '';

CREATE UNIQUE INDEX idx_regression_cases_exploit ON regression_cases (exploit_id);

-- One completed repeat. Never updated. evidence_json holds grader facts, not a transcript, cookie or credential.
CREATE TABLE regression_runs (
    id INTEGER PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES regression_cases (id),
    system_version TEXT NOT NULL CHECK (length(system_version) > 0),
    correlation_id TEXT NOT NULL CHECK (length(correlation_id) > 0),
    repeat_index INTEGER NOT NULL CHECK (repeat_index BETWEEN 1 AND 3),
    outcome TEXT NOT NULL CHECK (outcome IN ('pass', 'fail', 'not_exercised', 'wording_only')),
    invariant_id TEXT NOT NULL CHECK (length(invariant_id) > 0),
    http_status INTEGER,
    evidence_json TEXT NOT NULL CHECK (length(evidence_json) > 0),
    recorded_at TEXT NOT NULL,
    UNIQUE (case_id, system_version, repeat_index)
);

CREATE INDEX idx_regression_runs_case_version ON regression_runs (case_id, system_version);
CREATE INDEX idx_regression_runs_correlation ON regression_runs (correlation_id);

-- A draft report. publication status and remediation status are independent. fix_validation cites run ids.
CREATE TABLE reports (
    id TEXT PRIMARY KEY CHECK (length(id) > 0),
    exploit_id TEXT NOT NULL UNIQUE REFERENCES exploits (id),
    correlation_id TEXT NOT NULL CHECK (length(correlation_id) > 0),
    body TEXT NOT NULL CHECK (length(body) > 0),
    sequence_hash TEXT NOT NULL CHECK (length(sequence_hash) = 64),
    status TEXT NOT NULL CHECK (status IN ('draft', 'pending_approval', 'published', 'rejected')),
    remediation_status TEXT NOT NULL CHECK (remediation_status IN ('proposed', 'pending_authorization', 'authorized', 'rejected')),
    remediation_text TEXT NOT NULL CHECK (length(remediation_text) > 0),
    remediation_hash TEXT NOT NULL CHECK (length(remediation_hash) = 64),
    fix_validation TEXT NOT NULL CHECK (fix_validation IN ('not_run', 'not_fixed', 'fixed', 'regressed')),
    fix_validation_pin TEXT,
    evidence_run_ids TEXT NOT NULL DEFAULT '',
    held INTEGER NOT NULL DEFAULT 0 CHECK (held IN (0, 1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX idx_reports_correlation ON reports (correlation_id);
CREATE INDEX idx_reports_status ON reports (status);

-- One detection per handoff pin and case, so a resume cannot emit a second envelope.
CREATE TABLE regression_detections (
    id INTEGER PRIMARY KEY,
    target_pin TEXT NOT NULL CHECK (length(target_pin) > 0),
    case_id TEXT NOT NULL REFERENCES regression_cases (id),
    correlation_id TEXT NOT NULL CHECK (length(correlation_id) > 0),
    kind TEXT NOT NULL CHECK (kind IN ('reappearance', 'cross_category')),
    detail TEXT NOT NULL CHECK (length(detail) > 0),
    recorded_at TEXT NOT NULL,
    UNIQUE (target_pin, case_id)
);
