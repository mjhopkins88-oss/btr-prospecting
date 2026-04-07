-- Add columns for self-optimizing signal weight engine
ALTER TABLE signal_type_performance ADD COLUMN IF NOT EXISTS total_signals INTEGER DEFAULT 0;
ALTER TABLE signal_type_performance ADD COLUMN IF NOT EXISTS confirmed_predictions INTEGER DEFAULT 0;
ALTER TABLE signal_type_performance ADD COLUMN IF NOT EXISTS optimized_weight INTEGER DEFAULT 15;
