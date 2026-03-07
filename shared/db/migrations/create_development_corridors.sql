-- Development Corridor Intelligence: corridors table
-- Stores detected geographic development corridors.
CREATE TABLE IF NOT EXISTS development_corridors (
    id TEXT PRIMARY KEY,
    corridor_name TEXT NOT NULL,
    city TEXT,
    state TEXT,
    signal_density INTEGER DEFAULT 0,
    growth_rate REAL DEFAULT 0,
    dominant_development_type TEXT,
    metadata TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_dc_name ON development_corridors(corridor_name);
CREATE INDEX IF NOT EXISTS idx_dc_city ON development_corridors(city, state);
CREATE INDEX IF NOT EXISTS idx_dc_density ON development_corridors(signal_density DESC);
