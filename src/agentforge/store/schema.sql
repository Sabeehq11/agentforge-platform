-- P2 data model. Constraints and indexes only. No runner, no state machine, no role-scoped database users.
-- Applied by agentforge.store.migrate. Database files are git-ignored and are never committed.

CREATE TABLE exploits (
    id TEXT PRIMARY KEY,
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    category TEXT NOT NULL CHECK (category IN ('TM-PI', 'TM-EX', 'TM-SC', 'TM-TM', 'TM-DS', 'TM-ID')),
    reproduction_steps TEXT NOT NULL CHECK (length(reproduction_steps) > 0),
    observed_behavior TEXT NOT NULL CHECK (length(observed_behavior) > 0),
    expected_behavior TEXT NOT NULL CHECK (length(expected_behavior) > 0),
    sequence_hash TEXT NOT NULL CHECK (length(sequence_hash) = 64),
    system_version TEXT NOT NULL CHECK (length(system_version) > 0),
    status TEXT NOT NULL CHECK (status IN ('draft', 'pending_approval', 'published', 'rejected'))
);

CREATE UNIQUE INDEX idx_exploits_sequence_hash ON exploits (sequence_hash);
CREATE INDEX idx_exploits_severity ON exploits (severity);
CREATE INDEX idx_exploits_category ON exploits (category);
CREATE INDEX idx_exploits_system_version ON exploits (system_version);

CREATE TABLE regression_cases (
    id TEXT PRIMARY KEY,
    exploit_id TEXT NOT NULL REFERENCES exploits (id),
    category TEXT NOT NULL CHECK (category IN ('TM-PI', 'TM-EX', 'TM-SC', 'TM-TM', 'TM-DS', 'TM-ID')),
    expected_safe_behavior TEXT NOT NULL CHECK (length(expected_safe_behavior) > 0),
    system_version TEXT NOT NULL CHECK (length(system_version) > 0)
);

CREATE INDEX idx_regression_cases_category ON regression_cases (category);
CREATE INDEX idx_regression_cases_system_version ON regression_cases (system_version);

-- States are names. The machine that moves them is P6.
CREATE TABLE run_logs (
    id INTEGER PRIMARY KEY,
    correlation_id TEXT NOT NULL CHECK (length(correlation_id) > 0),
    agent_role TEXT NOT NULL CHECK (agent_role IN ('orchestrator', 'red_team', 'judge', 'documentation', 'harness')),
    state TEXT NOT NULL CHECK (state IN ('queued', 'running', 'halted', 'done')),
    error_code TEXT CHECK (
        error_code IS NULL OR error_code IN (
            'target_unreachable', 'budget_exceeded', 'judge_timeout',
            'no_findings_in_window', 'regression_detected'
        )
    ),
    started_at TEXT NOT NULL,
    finished_at TEXT
);

CREATE INDEX idx_run_logs_correlation ON run_logs (correlation_id);

CREATE TABLE coverage_metrics (
    category TEXT NOT NULL CHECK (category IN ('TM-PI', 'TM-EX', 'TM-SC', 'TM-TM', 'TM-DS', 'TM-ID')),
    system_version TEXT NOT NULL CHECK (length(system_version) > 0),
    case_count INTEGER NOT NULL CHECK (case_count >= 0),
    pass_count INTEGER NOT NULL CHECK (pass_count >= 0),
    fail_count INTEGER NOT NULL CHECK (fail_count >= 0),
    PRIMARY KEY (category, system_version)
);

CREATE TABLE schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL,
    note_path TEXT NOT NULL
);
