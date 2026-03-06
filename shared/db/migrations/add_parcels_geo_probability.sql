-- Add latitude, longitude, and development_probability to parcels table
-- These columns support the parcel intelligence layer and probability scoring
ALTER TABLE parcels ADD COLUMN IF NOT EXISTS address TEXT;
ALTER TABLE parcels ADD COLUMN IF NOT EXISTS latitude REAL;
ALTER TABLE parcels ADD COLUMN IF NOT EXISTS longitude REAL;
ALTER TABLE parcels ADD COLUMN IF NOT EXISTS development_probability INTEGER DEFAULT 0;
