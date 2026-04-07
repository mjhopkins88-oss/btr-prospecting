CREATE TABLE IF NOT EXISTS contractor_activity (
    id TEXT PRIMARY KEY,
    firm_id TEXT,
    parcel_id TEXT,
    activity_type TEXT,
    activity_date TIMESTAMP,
    source TEXT,
    metadata TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_ca_firm ON contractor_activity(firm_id);
CREATE INDEX IF NOT EXISTS idx_ca_parcel ON contractor_activity(parcel_id);
CREATE INDEX IF NOT EXISTS idx_ca_type ON contractor_activity(activity_type);
