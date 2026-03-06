-- Signal Sources table
-- Tracks all data sources and their prediction accuracy over time.
-- Used by the Signal Quality Ranking Engine to prioritize high-value collectors.
CREATE TABLE IF NOT EXISTS signal_sources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_name TEXT NOT NULL,
    source_type TEXT NOT NULL,
    city TEXT,
    state TEXT,
    signals_generated INT DEFAULT 0,
    signals_confirmed INT DEFAULT 0,
    accuracy_score FLOAT DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_signal_sources_name
    ON signal_sources (source_name);

CREATE INDEX IF NOT EXISTS idx_signal_sources_type
    ON signal_sources (source_type);

CREATE INDEX IF NOT EXISTS idx_signal_sources_accuracy
    ON signal_sources (accuracy_score DESC);
