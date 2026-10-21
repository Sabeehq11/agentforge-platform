-- R1 category pin. Additive. No v1 contract change.
-- request_json.category stays a real category. category_pinned = 0 means that value is a placeholder.

ALTER TABLE campaigns ADD COLUMN category_pinned INTEGER NOT NULL DEFAULT 1 CHECK (category_pinned IN (0, 1));

-- R2 mutation claim. One accepted mutation consumes one parent. A resume cannot select it again.

CREATE TABLE mutation_claims (
    signal_id INTEGER PRIMARY KEY REFERENCES signals (id),
    correlation_id TEXT NOT NULL,
    claimed_at TEXT NOT NULL
);
