-- Developer Intent Signals table
-- Stores early developer preparation signals detected before land acquisition
CREATE TABLE IF NOT EXISTS developer_intent_signals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    developer_id UUID,
    signal_type TEXT,
    city TEXT,
    state TEXT,
    related_entity TEXT,
    signal_strength INT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dis_developer ON developer_intent_signals(developer_id);
CREATE INDEX IF NOT EXISTS idx_dis_city_state ON developer_intent_signals(city, state);
CREATE INDEX IF NOT EXISTS idx_dis_signal_type ON developer_intent_signals(signal_type);
CREATE INDEX IF NOT EXISTS idx_dis_created ON developer_intent_signals(created_at DESC);
