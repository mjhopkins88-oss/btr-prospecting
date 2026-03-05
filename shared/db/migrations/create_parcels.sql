CREATE TABLE IF NOT EXISTS parcels (
    id TEXT PRIMARY KEY,
    parcel_id TEXT,
    city TEXT,
    state TEXT,
    acreage REAL,
    zoning TEXT,
    owner_name TEXT,
    owner_type TEXT,
    last_sale_date TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_parcels_parcel_id ON parcels(parcel_id);
CREATE INDEX IF NOT EXISTS idx_parcels_city ON parcels(city, state);
