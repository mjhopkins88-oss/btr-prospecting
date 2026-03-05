CREATE TABLE IF NOT EXISTS contractor_firms (
    id TEXT PRIMARY KEY,
    firm_name TEXT,
    firm_type TEXT,
    headquarters_city TEXT,
    headquarters_state TEXT,
    typical_project_type TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_cf_name ON contractor_firms(firm_name);
CREATE INDEX IF NOT EXISTS idx_cf_type ON contractor_firms(firm_type);
