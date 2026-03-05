CREATE TABLE IF NOT EXISTS contractor_developer_relationships (
    id TEXT PRIMARY KEY,
    contractor_id TEXT,
    developer_id TEXT,
    project_count INTEGER DEFAULT 0,
    relationship_strength INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_cdr_contractor ON contractor_developer_relationships(contractor_id);
CREATE INDEX IF NOT EXISTS idx_cdr_developer ON contractor_developer_relationships(developer_id);
