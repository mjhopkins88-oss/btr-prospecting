-- Capital Signals table
-- Stores raw capital flow signals from various sources before analysis
CREATE TABLE IF NOT EXISTS capital_signals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    developer_id UUID,
    signal_type TEXT,
    city TEXT,
    state TEXT,
    signal_strength INT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cs_developer ON capital_signals(developer_id);
CREATE INDEX IF NOT EXISTS idx_cs_city_state ON capital_signals(city, state);
CREATE INDEX IF NOT EXISTS idx_cs_signal_type ON capital_signals(signal_type);
CREATE INDEX IF NOT EXISTS idx_cs_created ON capital_signals(created_at DESC);
