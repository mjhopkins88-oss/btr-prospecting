-- Add zoning and contiguity analysis columns to parcel_context
-- Used by Zoning Intelligence Engine and Parcel Contiguity Engine
ALTER TABLE parcel_context ADD COLUMN IF NOT EXISTS zoning_analysis TEXT;
ALTER TABLE parcel_context ADD COLUMN IF NOT EXISTS contiguity_analysis TEXT;
