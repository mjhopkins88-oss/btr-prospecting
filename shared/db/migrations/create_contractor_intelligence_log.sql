CREATE TABLE IF NOT EXISTS contractor_intelligence_log (
    id TEXT PRIMARY KEY,
    parcel_id TEXT,
    contractor_id TEXT,
    activity_detected TEXT,
    confidence INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
