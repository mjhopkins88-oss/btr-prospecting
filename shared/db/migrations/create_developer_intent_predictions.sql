-- Developer Intent Predictions table
-- Stores predicted future project launches based on intent signal analysis
CREATE TABLE IF NOT EXISTS developer_intent_predictions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    developer_id UUID,
    predicted_city TEXT,
    predicted_state TEXT,
    signal_count INT,
    confidence_score INT,
    reasoning TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dip_developer ON developer_intent_predictions(developer_id);
CREATE INDEX IF NOT EXISTS idx_dip_city_state ON developer_intent_predictions(predicted_city, predicted_state);
CREATE INDEX IF NOT EXISTS idx_dip_confidence ON developer_intent_predictions(confidence_score DESC);
CREATE INDEX IF NOT EXISTS idx_dip_created ON developer_intent_predictions(created_at DESC);
