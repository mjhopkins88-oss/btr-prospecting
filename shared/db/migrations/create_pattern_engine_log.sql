-- Pattern Engine Log table
-- Tracks pattern detection runs for auditing and debugging
CREATE TABLE IF NOT EXISTS pattern_engine_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    parcel_id TEXT,
    pattern_id UUID,
    detection_time TIMESTAMP,
    confidence INT,
    notes TEXT
);
