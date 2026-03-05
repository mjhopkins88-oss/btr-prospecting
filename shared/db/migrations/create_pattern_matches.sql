-- Pattern Matches table
-- Stores detected pattern matches linking parcels to known development patterns
CREATE TABLE IF NOT EXISTS pattern_matches (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    parcel_id TEXT,
    pattern_id UUID,
    match_confidence INT,
    signals_detected INT,
    first_signal_date TIMESTAMP,
    last_signal_date TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pm_parcel ON pattern_matches(parcel_id);
CREATE INDEX IF NOT EXISTS idx_pm_pattern ON pattern_matches(pattern_id);
CREATE INDEX IF NOT EXISTS idx_pm_confidence ON pattern_matches(match_confidence DESC);
