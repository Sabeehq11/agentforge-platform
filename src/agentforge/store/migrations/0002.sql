-- Per-agent reserved and incurred spend. Reserved and incurred are not summed.
-- A released row keeps incurred_usd at 0. P8 still owns the query surface.

CREATE TABLE agent_spend (
    call_id TEXT PRIMARY KEY,
    agent_role TEXT NOT NULL CHECK (agent_role IN ('red_team', 'judge', 'target')),
    reserved_usd REAL NOT NULL CHECK (reserved_usd >= 0),
    incurred_usd REAL NOT NULL CHECK (incurred_usd >= 0),
    state TEXT NOT NULL CHECK (state IN ('reserved', 'incurred', 'released'))
);

CREATE INDEX idx_agent_spend_role ON agent_spend (agent_role);
