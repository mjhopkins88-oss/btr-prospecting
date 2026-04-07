-- Signal Type Performance table
-- Aggregated accuracy metrics per signal type.
-- Updated by the Signal Quality Engine.
CREATE TABLE IF NOT EXISTS signal_type_performance (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    signal_type TEXT NOT NULL UNIQUE,
    signals_generated INT DEFAULT 0,
    signals_confirmed INT DEFAULT 0,
    accuracy_score FLOAT DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_signal_type_performance_accuracy
    ON signal_type_performance (accuracy_score DESC);
