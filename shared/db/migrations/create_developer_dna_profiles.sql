CREATE TABLE IF NOT EXISTS developer_dna_profiles (
    id TEXT PRIMARY KEY,
    developer_id TEXT,
    preferred_states TEXT,
    preferred_cities TEXT,
    typical_unit_range TEXT,
    typical_project_types TEXT,
    average_project_size INTEGER,
    expansion_rate REAL,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_ddna_developer ON developer_dna_profiles(developer_id);
