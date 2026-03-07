"""
Developer Expansion Forecasting Engine.
Predicts where developers will build next based on historical activity.

Example logic:
  If developer builds in Phoenix and Austin, predict Dallas and Nashville.

Uses developer DNA profiles and geographic proximity to forecast
expansion markets.
"""
import json
import uuid
from collections import defaultdict
from datetime import datetime

from db import get_db


# Market adjacency graph — developers often expand to nearby markets
MARKET_ADJACENCY = {
    'Phoenix': ['Tucson', 'Las Vegas', 'Denver', 'Dallas'],
    'Dallas': ['Austin', 'Houston', 'San Antonio', 'Nashville'],
    'Austin': ['Dallas', 'San Antonio', 'Houston', 'Nashville'],
    'Atlanta': ['Charlotte', 'Nashville', 'Raleigh', 'Tampa'],
    'Charlotte': ['Raleigh', 'Atlanta', 'Nashville', 'Greenville'],
    'Nashville': ['Charlotte', 'Atlanta', 'Dallas', 'Raleigh'],
    'Tampa': ['Orlando', 'Jacksonville', 'Atlanta', 'Charlotte'],
    'Denver': ['Phoenix', 'Dallas', 'Salt Lake City', 'Austin'],
    'Raleigh': ['Charlotte', 'Atlanta', 'Nashville', 'Richmond'],
    'Orlando': ['Tampa', 'Jacksonville', 'Atlanta', 'Charlotte'],
}


def _get_developer_markets():
    """Get active markets for each developer from property signals."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute('''
        SELECT entity_name, city, state, COUNT(*) as signal_count
        FROM property_signals
        WHERE entity_name IS NOT NULL AND entity_name != ''
        AND city IS NOT NULL AND city != ''
        GROUP BY entity_name, city, state
        HAVING COUNT(*) >= 2
        ORDER BY entity_name
    ''')
    rows = cur.fetchall()
    conn.close()

    developer_markets = defaultdict(list)
    for entity, city, state, count in rows:
        developer_markets[entity].append({
            'city': city, 'state': state, 'signal_count': count,
        })
    return developer_markets


def _predict_expansion(developer, active_markets):
    """Predict likely expansion markets for a developer."""
    active_cities = {m['city'] for m in active_markets}
    predictions = defaultdict(float)

    for market in active_markets:
        city = market['city']
        adjacent = MARKET_ADJACENCY.get(city, [])
        for adj_city in adjacent:
            if adj_city not in active_cities:
                # Score based on adjacency frequency and developer signal strength
                predictions[adj_city] += market['signal_count'] * 0.3

    # Normalize to 0-100
    if not predictions:
        return []

    max_score = max(predictions.values())
    results = []
    for city, raw_score in predictions.items():
        normalized = min(int((raw_score / max(max_score, 1)) * 80), 95)
        if normalized >= 30:
            results.append({
                'city': city,
                'expansion_probability': normalized,
            })

    results.sort(key=lambda x: x['expansion_probability'], reverse=True)
    return results[:5]


def run_expansion_forecasting():
    """Predict expansion markets for all tracked developers."""
    print(f"[ExpansionEngine] START — {datetime.utcnow().isoformat()}")

    developer_markets = _get_developer_markets()
    total_predictions = 0

    conn = get_db()
    cur = conn.cursor()

    for developer, markets in developer_markets.items():
        if len(markets) < 2:
            continue

        predictions = _predict_expansion(developer, markets)
        if not predictions:
            continue

        # Store predictions
        for pred in predictions:
            try:
                cur.execute('''
                    INSERT OR IGNORE INTO property_signals
                    (id, signal_type, source, entity_name, city,
                     metadata, created_at)
                    VALUES (?, 'DEVELOPER_EXPANSION', 'expansion_forecast', ?,
                            ?, ?, CURRENT_TIMESTAMP)
                ''', (
                    str(uuid.uuid4()), developer, pred['city'],
                    json.dumps({
                        'developer': developer,
                        'predicted_city': pred['city'],
                        'expansion_probability': pred['expansion_probability'],
                        'active_markets': [m['city'] for m in markets],
                        'source_collector': 'developer_expansion_engine',
                    }),
                ))
                total_predictions += 1
            except Exception:
                pass

        # Emit event for high-confidence predictions
        top = predictions[0]
        if top['expansion_probability'] >= 60:
            try:
                from app import log_intelligence_event
                log_intelligence_event(
                    event_type='DEVELOPER_EXPANSION',
                    title=f"Expansion predicted: {developer} → {top['city']}",
                    description=(
                        f"Active in {', '.join(m['city'] for m in markets[:3])}. "
                        f"Expansion probability: {top['expansion_probability']}%"
                    ),
                    city=top['city'],
                    related_entity=developer,
                )
            except Exception:
                pass

    conn.commit()
    conn.close()
    print(f"[ExpansionEngine] Generated {total_predictions} expansion predictions")
    return {'predictions': total_predictions}
