"""
Developer Expansion Predictor.
Predicts likely next markets for developers based on DNA profiles,
geographic proximity, and active market signals.
"""
import json
import uuid
from datetime import datetime

from db import get_db


def _load_dna_profiles(cur):
    """Load all developer DNA profiles with developer info."""
    cur.execute('''
        SELECT dp.id, dp.developer_id, dp.preferred_states, dp.preferred_cities,
               dp.average_project_size, dp.expansion_rate,
               d.developer_name
        FROM developer_dna_profiles dp
        JOIN developers d ON d.id = dp.developer_id
    ''')
    cols = [desc[0] for desc in cur.description]
    profiles = []
    for row in cur.fetchall():
        p = dict(zip(cols, row))
        # Parse JSON fields
        for field in ('preferred_states', 'preferred_cities'):
            try:
                p[field] = json.loads(p[field]) if isinstance(p[field], str) else (p[field] or [])
            except Exception:
                p[field] = []
        profiles.append(p)
    return profiles


def _get_active_signal_cities(cur):
    """Get cities with recent development signals (last 90 days)."""
    cur.execute('''
        SELECT DISTINCT city, state FROM development_events
        WHERE city IS NOT NULL AND state IS NOT NULL
        AND created_at >= CURRENT_TIMESTAMP - INTERVAL '90 days'
    ''')
    return [(r[0], r[1]) for r in cur.fetchall()]


def _get_active_signal_cities_fallback(cur):
    """Fallback for SQLite which doesn't support INTERVAL."""
    cur.execute('''
        SELECT DISTINCT city, state FROM development_events
        WHERE city IS NOT NULL AND state IS NOT NULL
    ''')
    return [(r[0], r[1]) for r in cur.fetchall()]


def _get_market_cities(cur):
    """Get cities from the markets table that are being tracked."""
    try:
        cur.execute('SELECT city, state FROM markets WHERE market_score >= 50')
        return [(r[0], r[1]) for r in cur.fetchall()]
    except Exception:
        return []


def _developer_already_in_city(cur, developer_id, city, state):
    """Check if developer already has projects in this city."""
    cur.execute('''
        SELECT COUNT(*) FROM developer_project_history
        WHERE developer_id = ? AND city = ? AND state = ?
    ''', (developer_id, city, state))
    return cur.fetchone()[0] > 0


def _compute_expansion_confidence(profile, city, state):
    """
    Score how likely a developer is to expand into a given city/state.
    Based on:
    - State match with preferred states (+30)
    - Adjacent to existing cities (+25)
    - High expansion rate (+20)
    - Active market signals (+15)
    - Base score (10)
    """
    confidence = 10  # base

    preferred_states = profile.get('preferred_states', [])
    preferred_cities = profile.get('preferred_cities', [])

    # State match
    if state in preferred_states:
        confidence += 30

    # City adjacency — check if developer has projects in same state
    same_state_cities = [
        c for c in preferred_cities
        if c.endswith(f',{state}')
    ]
    if same_state_cities:
        confidence += 25

    # Expansion rate factor
    expansion_rate = profile.get('expansion_rate', 0)
    if expansion_rate >= 3.0:
        confidence += 20
    elif expansion_rate >= 1.5:
        confidence += 10

    return min(100, confidence)


def _generate_reasoning(profile, city, state, confidence):
    """Generate human-readable reasoning for a prediction."""
    parts = []
    preferred_states = profile.get('preferred_states', [])
    preferred_cities = profile.get('preferred_cities', [])
    expansion_rate = profile.get('expansion_rate', 0)

    if state in preferred_states:
        existing_in_state = [c.split(',')[0] for c in preferred_cities if c.endswith(f',{state}')]
        if existing_in_state:
            parts.append(f"Developer has built {len(existing_in_state)} projects in {state} ({', '.join(existing_in_state[:3])})")

    if expansion_rate >= 1.5:
        parts.append(f"High expansion rate ({expansion_rate} new markets/year)")

    if not parts:
        parts.append(f"Developer active in adjacent markets")

    parts.append(f"Signals detected in {city}, {state}")
    return '. '.join(parts)


def predict_expansions():
    """
    Main entry point: predict developer expansions.
    For each developer with a DNA profile, check signal cities
    they haven't built in yet and score likelihood.
    """
    print(f"[Expansion Predictor] START — {datetime.utcnow().isoformat()}")

    conn = get_db()
    cur = conn.cursor()

    profiles = _load_dna_profiles(cur)
    print(f"[Expansion Predictor] Loaded {len(profiles)} DNA profiles")

    # Get candidate cities from signals and markets
    try:
        signal_cities = _get_active_signal_cities(cur)
    except Exception:
        signal_cities = _get_active_signal_cities_fallback(cur)

    market_cities = _get_market_cities(cur)
    candidate_cities = list(set(signal_cities + market_cities))
    print(f"[Expansion Predictor] {len(candidate_cities)} candidate cities")

    # Clear old predictions
    cur.execute('DELETE FROM developer_expansion_predictions')

    predictions_made = 0

    for profile in profiles:
        developer_id = profile['developer_id']
        developer_name = profile.get('developer_name', 'Unknown')

        for city, state in candidate_cities:
            if _developer_already_in_city(cur, developer_id, city, state):
                continue

            confidence = _compute_expansion_confidence(profile, city, state)

            # Only store predictions with meaningful confidence
            if confidence < 40:
                continue

            reasoning = _generate_reasoning(profile, city, state, confidence)

            cur.execute('''
                INSERT INTO developer_expansion_predictions
                (id, developer_id, predicted_city, predicted_state, confidence, reasoning)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (str(uuid.uuid4()), developer_id, city, state, confidence, reasoning))

            # Log the prediction
            cur.execute('''
                INSERT INTO developer_dna_log
                (id, developer_id, prediction_city, prediction_confidence)
                VALUES (?, ?, ?, ?)
            ''', (str(uuid.uuid4()), developer_id, city, confidence))

            predictions_made += 1

    conn.commit()
    conn.close()

    print(f"[Expansion Predictor] COMPLETE — {predictions_made} predictions generated")
    return {'predictions': predictions_made}
