-- Development Patterns table
-- Stores known signal sequences that precede BTR developments
CREATE TABLE IF NOT EXISTS development_patterns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pattern_name TEXT,
    signal_sequence TEXT[],
    time_window_days INT,
    base_confidence INT,
    description TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

INSERT INTO development_patterns (pattern_name, signal_sequence, time_window_days, base_confidence, description)
VALUES (
    'BTR_EARLY_DEVELOPMENT',
    ARRAY['LAND_PURCHASE','ZONING_CASE','SUBDIVISION_PLAT'],
    90,
    85,
    'Typical early signal sequence preceding build-to-rent development'
)
ON CONFLICT DO NOTHING;

INSERT INTO development_patterns (pattern_name, signal_sequence, time_window_days, base_confidence, description)
VALUES (
    'BTR_CONFIRMED_DEVELOPMENT',
    ARRAY['LAND_PURCHASE','ZONING_CASE','SUBDIVISION_PLAT','PERMIT_APPLICATION'],
    180,
    95,
    'Full confirmed BTR development sequence with permit'
)
ON CONFLICT DO NOTHING;
