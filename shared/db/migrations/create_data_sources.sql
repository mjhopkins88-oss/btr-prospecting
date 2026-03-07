-- Data Sources table
-- Stores discovered public data sources for signal collection.
-- Populated by the Source Discovery Engine.
CREATE TABLE IF NOT EXISTS data_sources (
    id TEXT PRIMARY KEY,
    source_type TEXT NOT NULL,
    city TEXT,
    state TEXT,
    title TEXT,
    url TEXT UNIQUE,
    description TEXT,
    priority INTEGER DEFAULT 50,
    status TEXT DEFAULT 'discovered',
    reliability_score REAL DEFAULT 0,
    last_checked TIMESTAMP,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_data_sources_city ON data_sources(city, state);
CREATE INDEX IF NOT EXISTS idx_data_sources_type ON data_sources(source_type);
CREATE INDEX IF NOT EXISTS idx_data_sources_status ON data_sources(status);
