-- Property Signals table
-- Normalized signals from free government data sources:
-- city planning portals, building permits, zoning boards,
-- secretary of state filings, engineering activity, news
CREATE TABLE IF NOT EXISTS property_signals (
    id TEXT PRIMARY KEY,
    parcel_id TEXT,
    signal_type TEXT NOT NULL,
    source TEXT,
    entity_name TEXT,
    address TEXT,
    city TEXT,
    state TEXT,
    metadata TEXT,  -- JSON
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_property_signals_parcel ON property_signals(parcel_id);
CREATE INDEX IF NOT EXISTS idx_property_signals_type ON property_signals(signal_type);
CREATE INDEX IF NOT EXISTS idx_property_signals_city ON property_signals(city, state);
CREATE INDEX IF NOT EXISTS idx_property_signals_created ON property_signals(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_property_signals_entity ON property_signals(entity_name);
