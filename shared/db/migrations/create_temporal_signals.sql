-- Temporal Signals table
-- Stores individual signal events with timestamps for temporal analysis.
-- Each row represents a single intelligence signal detected by the platform.
CREATE TABLE IF NOT EXISTS temporal_signals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    signal_type TEXT,
    entity_id TEXT,
    city TEXT,
    state TEXT,
    signal_source TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ts_signal_type ON temporal_signals(signal_type);
CREATE INDEX IF NOT EXISTS idx_ts_entity ON temporal_signals(entity_id);
CREATE INDEX IF NOT EXISTS idx_ts_city_state ON temporal_signals(city, state);
CREATE INDEX IF NOT EXISTS idx_ts_created ON temporal_signals(created_at DESC);
