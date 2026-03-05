-- Temporal Signal Sequences table
-- Stores learned signal orderings extracted from confirmed developments.
-- The learner analyzes which signal types appeared, in what order, and
-- with what timing before a development was confirmed.
CREATE TABLE IF NOT EXISTS temporal_signal_sequences (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sequence_name TEXT,
    signal_steps TEXT,
    avg_step_gap_days TEXT,
    total_window_days INT,
    occurrences INT DEFAULT 1,
    success_rate NUMERIC(5,2) DEFAULT 0,
    source_predictions TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tss_occurrences ON temporal_signal_sequences(occurrences DESC);
CREATE INDEX IF NOT EXISTS idx_tss_success_rate ON temporal_signal_sequences(success_rate DESC);

-- Add temporal boost columns to predicted_project_index
ALTER TABLE predicted_project_index ADD COLUMN IF NOT EXISTS temporal_boost INT DEFAULT 0;
ALTER TABLE predicted_project_index ADD COLUMN IF NOT EXISTS temporal_pattern_match TEXT DEFAULT '';
ALTER TABLE predicted_project_index ADD COLUMN IF NOT EXISTS temporal_match_stage TEXT DEFAULT '';
