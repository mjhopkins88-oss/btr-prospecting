CREATE TABLE IF NOT EXISTS sales_leads (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    developer TEXT,
    city TEXT,
    state TEXT,
    lead_score INT,
    lead_summary TEXT,
    source_signal TEXT,
    confidence INT,
    created_at TIMESTAMP DEFAULT NOW()
);
