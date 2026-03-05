-- Capital Events table
-- Stores detected financing events linked to development projects
CREATE TABLE IF NOT EXISTS capital_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    developer_id UUID,
    company_name TEXT,
    event_type TEXT,
    city TEXT,
    state TEXT,
    loan_amount FLOAT,
    lender_name TEXT,
    related_project TEXT,
    source TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ce_developer ON capital_events(developer_id);
CREATE INDEX IF NOT EXISTS idx_ce_city_state ON capital_events(city, state);
CREATE INDEX IF NOT EXISTS idx_ce_event_type ON capital_events(event_type);
CREATE INDEX IF NOT EXISTS idx_ce_created ON capital_events(created_at DESC);
