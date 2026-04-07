-- Developer Network Intelligence: network edges table
-- Stores relationship graph edges between developers, contractors,
-- engineers, architects, lenders, and suppliers.
CREATE TABLE IF NOT EXISTS developer_network_edges (
    id TEXT PRIMARY KEY,
    entity_a TEXT NOT NULL,
    entity_b TEXT NOT NULL,
    relationship_type TEXT NOT NULL,
    co_occurrence_count INTEGER DEFAULT 1,
    last_seen TIMESTAMP,
    relationship_strength INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_dne_entity_a ON developer_network_edges(entity_a);
CREATE INDEX IF NOT EXISTS idx_dne_entity_b ON developer_network_edges(entity_b);
CREATE INDEX IF NOT EXISTS idx_dne_strength ON developer_network_edges(relationship_strength DESC);
CREATE INDEX IF NOT EXISTS idx_dne_type ON developer_network_edges(relationship_type);
