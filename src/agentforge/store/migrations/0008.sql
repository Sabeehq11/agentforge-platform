-- Replayable grades for authorized synthetic fixtures. Additive. No v1 contract change.
-- signals stays findings only (fail and partial). A pass is not a finding and is not counted as one.
-- The transcript is stored only after the PHI scan. A match refuses the write. The row is not a published report.

CREATE TABLE graded_transcripts (
    id INTEGER PRIMARY KEY,
    correlation_id TEXT NOT NULL REFERENCES campaigns (correlation_id),
    transcript_id TEXT NOT NULL,
    subcategory TEXT NOT NULL CHECK (length(subcategory) > 0),
    verdict TEXT NOT NULL CHECK (verdict IN ('pass', 'fail', 'partial')),
    evidence_hash TEXT NOT NULL CHECK (length(evidence_hash) = 64),
    transcript_json TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    UNIQUE (correlation_id, transcript_id)
);

CREATE INDEX idx_graded_transcripts_correlation ON graded_transcripts (correlation_id);
