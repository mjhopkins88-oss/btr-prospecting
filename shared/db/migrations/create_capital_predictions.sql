-- Capital Predictions table
-- Stores predicted capital deployment events linked to developers and markets
CREATE TABLE IF NOT EXISTS capital_predictions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    developer_id UUID,
    predicted_city TEXT,
    predicted_state TEXT,
    capital_event_type TEXT,
    estimated_capital_amount FLOAT,
    confidence_score INT,
    reasoning TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cp_developer ON capital_predictions(developer_id);
CREATE INDEX IF NOT EXISTS idx_cp_city_state ON capital_predictions(predicted_city, predicted_state);
CREATE INDEX IF NOT EXISTS idx_cp_confidence ON capital_predictions(confidence_score DESC);
CREATE INDEX IF NOT EXISTS idx_cp_created ON capital_predictions(created_at DESC);
