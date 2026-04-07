CREATE TABLE IF NOT EXISTS parcel_development_probability (
    id TEXT PRIMARY KEY,
    parcel_id TEXT,
    probability_score INTEGER,
    likely_development_type TEXT,
    reasoning TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_pdp_parcel ON parcel_development_probability(parcel_id);
CREATE INDEX IF NOT EXISTS idx_pdp_score ON parcel_development_probability(probability_score DESC);
