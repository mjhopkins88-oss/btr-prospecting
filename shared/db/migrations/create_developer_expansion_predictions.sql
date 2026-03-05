CREATE TABLE IF NOT EXISTS developer_expansion_predictions (
    id TEXT PRIMARY KEY,
    developer_id TEXT,
    predicted_city TEXT,
    predicted_state TEXT,
    confidence INTEGER,
    reasoning TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_dep_developer ON developer_expansion_predictions(developer_id);
CREATE INDEX IF NOT EXISTS idx_dep_city ON developer_expansion_predictions(predicted_city, predicted_state);
