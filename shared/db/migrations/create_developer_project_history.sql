CREATE TABLE IF NOT EXISTS developer_project_history (
    id TEXT PRIMARY KEY,
    developer_id TEXT,
    project_name TEXT,
    city TEXT,
    state TEXT,
    parcel_id TEXT,
    project_type TEXT,
    unit_count INTEGER,
    square_feet INTEGER,
    project_stage TEXT,
    first_detected TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_dph_developer ON developer_project_history(developer_id);
CREATE INDEX IF NOT EXISTS idx_dph_city ON developer_project_history(city, state);
