CREATE TABLE IF NOT EXISTS developer_dna_log (
    id TEXT PRIMARY KEY,
    developer_id TEXT,
    prediction_city TEXT,
    prediction_confidence INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
