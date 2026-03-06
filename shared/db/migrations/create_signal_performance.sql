-- Signal Performance table
-- Tracks whether individual signals eventually lead to real developments.
-- Fed by the Development Confirmation Engine.
CREATE TABLE IF NOT EXISTS signal_performance (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    signal_id UUID,
    source_name TEXT,
    signal_type TEXT,
    parcel_id TEXT,
    predicted_development BOOLEAN DEFAULT FALSE,
    confirmed_development BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_signal_performance_source
    ON signal_performance (source_name);

CREATE INDEX IF NOT EXISTS idx_signal_performance_type
    ON signal_performance (signal_type);

CREATE INDEX IF NOT EXISTS idx_signal_performance_parcel
    ON signal_performance (parcel_id);
