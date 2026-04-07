-- Pattern Signal History table
-- Stores normalized signal events used for pattern matching
CREATE TABLE IF NOT EXISTS pattern_signal_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    parcel_id TEXT,
    signal_type TEXT,
    signal_date TIMESTAMP,
    source TEXT,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_psh_parcel ON pattern_signal_history(parcel_id);
CREATE INDEX IF NOT EXISTS idx_psh_type ON pattern_signal_history(signal_type);
CREATE INDEX IF NOT EXISTS idx_psh_date ON pattern_signal_history(signal_date DESC);
