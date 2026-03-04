"""
Market Scoring Engine.
Calculates market_score for cities based on growth indicators
and developer activity signals.
"""
from db import get_db


def score_market(city, state, population_growth=0, permit_growth=0, rent_growth=0):
    """
    Calculate market score using:
    - population_growth (% YoY)
    - permit_growth (% YoY)
    - rent_growth (% YoY)
    - developer activity nearby (from development_events)

    Returns integer score 0-100.
    """
    score = 0

    # Population growth scoring
    if population_growth > 3:
        score += 30
    elif population_growth > 2:
        score += 25
    elif population_growth > 1:
        score += 15

    # Permit growth scoring
    if permit_growth > 25:
        score += 25
    elif permit_growth > 15:
        score += 20
    elif permit_growth > 10:
        score += 12

    # Rent growth scoring
    if rent_growth > 8:
        score += 20
    elif rent_growth > 5:
        score += 15
    elif rent_growth > 3:
        score += 10

    # Developer activity nearby
    dev_boost = _check_developer_activity(city, state)
    score += dev_boost

    return min(score, 100)


def _check_developer_activity(city, state):
    """
    Check if known BTR developers are active in or near this city.
    Returns score boost (0-25).
    """
    try:
        conn = get_db()
        cur = conn.cursor()

        # Check development_events for this city
        cur.execute('''
            SELECT COUNT(DISTINCT developer) FROM development_events
            WHERE state = ? AND developer IS NOT NULL AND developer != ''
        ''', (state,))
        state_devs = cur.fetchone()[0]

        # Check for direct city matches
        cur.execute('''
            SELECT COUNT(*) FROM development_events
            WHERE city = ? AND state = ?
        ''', (city, state))
        city_events = cur.fetchone()[0]

        # Check entity_relationships for developer activity in state
        cur.execute('''
            SELECT COUNT(*) FROM entity_relationships
            WHERE relationship_type = 'DEVELOPER_ACTIVE_IN_CITY'
            AND entity_b LIKE ?
        ''', (f'%, {state}',))
        rel_count = cur.fetchone()[0]

        conn.close()

        boost = 0
        if city_events > 0:
            boost += 15
        if state_devs >= 3:
            boost += 10
        elif state_devs >= 1:
            boost += 5
        if rel_count >= 5:
            boost += 5

        return min(25, boost)
    except Exception:
        return 0


def score_all_cities():
    """
    Score all cities in city_growth_metrics.
    Returns list of (city, state, score) tuples.
    """
    conn = get_db()
    cur = conn.cursor()

    cur.execute('''
        SELECT city, state, population_growth, permit_growth, rent_growth
        FROM city_growth_metrics
    ''')
    rows = cur.fetchall()
    conn.close()

    results = []
    for row in rows:
        city, state, pop_g, perm_g, rent_g = row
        s = score_market(
            city, state,
            population_growth=pop_g or 0,
            permit_growth=perm_g or 0,
            rent_growth=rent_g or 0,
        )
        results.append((city, state, s))

    results.sort(key=lambda x: x[2], reverse=True)
    return results
