-- Intelligence Events table
-- Stores real-time feed events from all intelligence engines:
-- signal collectors, pattern detection, developer DNA, contractor intelligence,
-- parcel probability engine, market expansion engine
CREATE TABLE IF NOT EXISTS intelligence_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    city TEXT,
    state TEXT,
    related_entity TEXT,
    entity_id TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_intelligence_events_created
    ON intelligence_events (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_intelligence_events_type
    ON intelligence_events (event_type);
