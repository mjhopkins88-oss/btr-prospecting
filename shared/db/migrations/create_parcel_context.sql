CREATE TABLE IF NOT EXISTS parcel_context (
    id TEXT PRIMARY KEY,
    parcel_id TEXT,
    nearby_developments INTEGER,
    population_growth REAL,
    permit_growth REAL,
    infrastructure_projects INTEGER,
    development_pressure_score INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_pc_parcel ON parcel_context(parcel_id);
