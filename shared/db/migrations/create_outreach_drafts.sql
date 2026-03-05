CREATE TABLE IF NOT EXISTS outreach_drafts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    lead_id UUID,
    contact_id UUID,
    subject TEXT,
    email_body TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_outreach_drafts_lead_id ON outreach_drafts(lead_id);
CREATE INDEX IF NOT EXISTS idx_outreach_drafts_contact_id ON outreach_drafts(contact_id);
