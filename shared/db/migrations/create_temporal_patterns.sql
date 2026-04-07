-- Temporal Patterns table
-- Stores known signal sequences that historically precede real developments.
-- The engine matches incoming signals against these patterns.
CREATE TABLE IF NOT EXISTS temporal_patterns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pattern_name TEXT,
    signal_sequence TEXT[],
    average_time_window INT,
    confidence_score INT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Seed known BTR development patterns
INSERT INTO temporal_patterns (pattern_name, signal_sequence, average_time_window, confidence_score)
VALUES (
    'BTR_PRE_DEVELOPMENT_SEQUENCE',
    ARRAY['ENGINEERING_ENGAGEMENT','CONTRACTOR_ACTIVITY','PARCEL_PROBABILITY_SPIKE'],
    120,
    85
)
ON CONFLICT DO NOTHING;

INSERT INTO temporal_patterns (pattern_name, signal_sequence, average_time_window, confidence_score)
VALUES (
    'BTR_FULL_PIPELINE',
    ARRAY['ENGINEERING_ENGAGEMENT','CONTRACTOR_ACTIVITY','PARCEL_PROBABILITY_SPIKE','CAPITAL_DEPLOYMENT'],
    180,
    95
)
ON CONFLICT DO NOTHING;

INSERT INTO temporal_patterns (pattern_name, signal_sequence, average_time_window, confidence_score)
VALUES (
    'DEVELOPER_EXPANSION_SEQUENCE',
    ARRAY['DEVELOPER_INTENT','ENGINEERING_ENGAGEMENT','PERMIT_APPLICATION'],
    90,
    80
)
ON CONFLICT DO NOTHING;

INSERT INTO temporal_patterns (pattern_name, signal_sequence, average_time_window, confidence_score)
VALUES (
    'RAPID_DEVELOPMENT_SIGNAL',
    ARRAY['PERMIT_APPLICATION','CONTRACTOR_ACTIVITY','CAPITAL_DEPLOYMENT'],
    60,
    90
)
ON CONFLICT DO NOTHING;
