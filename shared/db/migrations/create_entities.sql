-- Entities table
-- Resolves developer LLCs to parent entities.
-- e.g. "Sunrise Greenville LLC" → parent "Sunrise Development"
CREATE TABLE IF NOT EXISTS entities (
    id TEXT PRIMARY KEY,
    entity_name TEXT NOT NULL,
    normalized_name TEXT,
    entity_type TEXT,  -- developer, llc, engineer, contractor, lender
    parent_entity TEXT,
    metadata TEXT,  -- JSON
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_entities_name ON entities(entity_name);
CREATE INDEX IF NOT EXISTS idx_entities_normalized ON entities(normalized_name);
CREATE INDEX IF NOT EXISTS idx_entities_parent ON entities(parent_entity);
CREATE INDEX IF NOT EXISTS idx_entities_type ON entities(entity_type);
