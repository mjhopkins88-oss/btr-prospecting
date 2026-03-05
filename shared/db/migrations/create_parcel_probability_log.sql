CREATE TABLE IF NOT EXISTS parcel_probability_log (
    id TEXT PRIMARY KEY,
    parcel_id TEXT,
    probability_score INTEGER,
    analysis_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    notes TEXT
);
