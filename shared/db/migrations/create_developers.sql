CREATE TABLE IF NOT EXISTS developers (
    id TEXT PRIMARY KEY,
    developer_name TEXT,
    headquarters_city TEXT,
    headquarters_state TEXT,
    total_projects INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_developers_name ON developers(developer_name);
