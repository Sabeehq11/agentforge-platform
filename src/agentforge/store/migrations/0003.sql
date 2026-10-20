-- P6 orchestrator state. New tables only. run_logs, the v1 contracts and every earlier table are untouched.
-- The journal stores hashes and statuses, never request bodies, cookies or credentials.

CREATE TABLE campaigns (
    correlation_id TEXT PRIMARY KEY CHECK (length(correlation_id) > 0),
    request_json TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN ('selecting', 'attacking', 'judging', 'recording', 'done', 'halted')),
    halt_reason TEXT,
    retryable INTEGER NOT NULL DEFAULT 0 CHECK (retryable IN (0, 1)),
    attempt INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    next_attempt_at TEXT,
    attacks_done INTEGER NOT NULL DEFAULT 0 CHECK (attacks_done >= 0),
    sequences_started INTEGER NOT NULL DEFAULT 0 CHECK (sequences_started >= 0),
    turns_sent INTEGER NOT NULL DEFAULT 0 CHECK (turns_sent >= 0),
    signal_count INTEGER NOT NULL DEFAULT 0 CHECK (signal_count >= 0),
    spent_usd REAL NOT NULL DEFAULT 0 CHECK (spent_usd >= 0),
    system_version TEXT NOT NULL CHECK (length(system_version) > 0),
    current_category TEXT,
    redirects INTEGER NOT NULL DEFAULT 0 CHECK (redirects >= 0),
    segment_attacks_base INTEGER NOT NULL DEFAULT 0 CHECK (segment_attacks_base >= 0),
    segment_spend_base REAL NOT NULL DEFAULT 0 CHECK (segment_spend_base >= 0),
    segment_signal_base INTEGER NOT NULL DEFAULT 0 CHECK (segment_signal_base >= 0),
    scores_json TEXT,
    note TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX idx_campaigns_phase ON campaigns (phase);

-- One row per external effect. call_id is deterministic: <role>-<correlation_id>-<step_no>-<attempt>.
CREATE TABLE dispatch_journal (
    id INTEGER PRIMARY KEY,
    correlation_id TEXT NOT NULL REFERENCES campaigns (correlation_id),
    step_no INTEGER NOT NULL CHECK (step_no >= 0),
    attempt INTEGER NOT NULL CHECK (attempt >= 0),
    call_id TEXT NOT NULL UNIQUE CHECK (length(call_id) > 0),
    role TEXT NOT NULL CHECK (role IN ('orchestrator', 'red_team', 'executor', 'judge')),
    kind TEXT NOT NULL CHECK (kind IN ('model', 'target', 'judge_model')),
    intent_hash TEXT NOT NULL CHECK (length(intent_hash) = 64),
    state TEXT NOT NULL CHECK (state IN ('intended', 'sent', 'completed', 'unknown', 'abandoned')),
    reserved_usd REAL NOT NULL DEFAULT 0 CHECK (reserved_usd >= 0),
    incurred_usd REAL NOT NULL DEFAULT 0 CHECK (incurred_usd >= 0),
    http_status INTEGER,
    retry_after_s REAL,
    output_hash TEXT,
    settlement TEXT NOT NULL DEFAULT 'none' CHECK (settlement IN ('none', 'pending', 'settled', 'released')),
    sequence_id TEXT,
    detail TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (correlation_id, step_no, attempt)
);

CREATE INDEX idx_dispatch_journal_correlation ON dispatch_journal (correlation_id);
CREATE INDEX idx_dispatch_journal_state ON dispatch_journal (state, settlement);

-- Validated security signals only. dedup_key counts a finding once.
CREATE TABLE signals (
    id INTEGER PRIMARY KEY,
    correlation_id TEXT NOT NULL REFERENCES campaigns (correlation_id),
    category TEXT NOT NULL CHECK (category IN ('TM-PI', 'TM-EX', 'TM-SC', 'TM-TM', 'TM-DS', 'TM-ID')),
    subcategory TEXT NOT NULL CHECK (length(subcategory) > 0),
    verdict TEXT NOT NULL CHECK (verdict IN ('fail', 'partial')),
    evidence_hash TEXT NOT NULL CHECK (length(evidence_hash) = 64),
    dedup_key TEXT NOT NULL UNIQUE,
    transcript_id TEXT NOT NULL,
    transcript_json TEXT NOT NULL,
    parent_id INTEGER REFERENCES signals (id),
    depth INTEGER NOT NULL DEFAULT 0 CHECK (depth >= 0),
    recorded_at TEXT NOT NULL
);

CREATE INDEX idx_signals_category ON signals (category);
CREATE INDEX idx_signals_correlation ON signals (correlation_id);

-- The first verified target pin. It is a baseline, not a change.
CREATE TABLE version_baselines (
    id INTEGER PRIMARY KEY,
    target_pin TEXT NOT NULL UNIQUE CHECK (length(target_pin) BETWEEN 7 AND 40),
    recorded_at TEXT NOT NULL,
    identity_checked_at TEXT NOT NULL,
    correlation_id TEXT NOT NULL
);

-- A later verified change. P6 records it. P7 claims it and replays regression cases.
CREATE TABLE version_handoffs (
    id INTEGER PRIMARY KEY,
    target_pin TEXT NOT NULL UNIQUE CHECK (length(target_pin) BETWEEN 7 AND 40),
    previous_pin TEXT NOT NULL CHECK (length(previous_pin) BETWEEN 7 AND 40),
    detected_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'claimed', 'done')),
    claimed_by TEXT,
    correlation_id TEXT NOT NULL
);

-- Every accepted generated attack, so novelty can compare against persisted variants and a parent's children can be
-- counted. Holds user turns only. Never a response, cookie or credential.
CREATE TABLE attack_variants (
    id INTEGER PRIMARY KEY,
    correlation_id TEXT NOT NULL REFERENCES campaigns (correlation_id),
    category TEXT NOT NULL CHECK (category IN ('TM-PI', 'TM-EX', 'TM-SC', 'TM-TM', 'TM-DS', 'TM-ID')),
    subcategory TEXT NOT NULL CHECK (length(subcategory) > 0),
    mode TEXT NOT NULL CHECK (mode IN ('novel', 'mutation', 'multi_turn', 'variant')),
    parent_signal_id INTEGER REFERENCES signals (id),
    depth INTEGER NOT NULL DEFAULT 0 CHECK (depth >= 0),
    turns_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX idx_attack_variants_category ON attack_variants (category);
CREATE INDEX idx_attack_variants_parent ON attack_variants (parent_signal_id);
