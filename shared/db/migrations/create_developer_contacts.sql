CREATE TABLE IF NOT EXISTS developer_contacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    developer_name TEXT,
    contact_name TEXT,
    title TEXT,
    email TEXT,
    linkedin_url TEXT,
    company_domain TEXT,
    confidence_score INT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_developer_contacts_developer_name ON developer_contacts(developer_name);
CREATE INDEX IF NOT EXISTS idx_developer_contacts_confidence_score ON developer_contacts(confidence_score DESC);
