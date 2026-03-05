ALTER TABLE predicted_project_index ADD COLUMN IF NOT EXISTS convergence_score INT DEFAULT 0;
ALTER TABLE predicted_project_index ADD COLUMN IF NOT EXISTS convergence_signal_count INT DEFAULT 0;
ALTER TABLE predicted_project_index ADD COLUMN IF NOT EXISTS convergence_signal_types TEXT DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_ppi_convergence_score ON predicted_project_index(convergence_score DESC);
