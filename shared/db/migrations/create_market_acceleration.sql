-- Market Acceleration tracking
-- Detects cities with spiking development signal activity
CREATE TABLE IF NOT EXISTS market_acceleration (
    id TEXT PRIMARY KEY,
    city TEXT NOT NULL,
    state TEXT NOT NULL,
    signals_90_days INTEGER DEFAULT 0,
    signals_12_months INTEGER DEFAULT 0,
    acceleration_ratio REAL DEFAULT 0,
    is_emerging INTEGER DEFAULT 0,
    last_calculated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_market_accel_city ON market_acceleration(city, state);
CREATE INDEX IF NOT EXISTS idx_market_accel_emerging ON market_acceleration(is_emerging);
CREATE INDEX IF NOT EXISTS idx_market_accel_ratio ON market_acceleration(acceleration_ratio DESC);
