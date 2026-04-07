-- Source Priority Index table
-- Ranks signal sources by value for collector prioritization.
-- Higher priority_score sources run more frequently.
CREATE TABLE IF NOT EXISTS source_priority_index (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_name TEXT NOT NULL UNIQUE,
    priority_score FLOAT DEFAULT 0,
    signals_last_30_days INT DEFAULT 0,
    accuracy_score FLOAT DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_source_priority_score
    ON source_priority_index (priority_score DESC);
