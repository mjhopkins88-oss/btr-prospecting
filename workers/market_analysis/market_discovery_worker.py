"""
Market Discovery Worker.
Scans city_growth_metrics, calculates market scores, identifies
high-potential cities (score >= 70), and inserts them into the markets table.
"""
import uuid
import json
import traceback
from datetime import datetime

from db import get_db
from workers.market_analysis.market_scoring_engine import score_market


def run_market_discovery():
    """
    Pipeline:
    1. Scan city_growth_metrics
    2. Calculate market_score for each city
    3. Identify cities with score >= 70
    4. Exclude cities already in markets table
    5. Insert new markets
    """
    print(f"\n{'='*60}")
    print(f"[MarketDiscovery] START — {datetime.utcnow().isoformat()}")
    print(f"{'='*60}\n")

    conn = get_db()
    cur = conn.cursor()

    # Get all city growth metrics
    cur.execute('''
        SELECT city, state, population, population_growth,
               housing_permits, permit_growth, median_rent, rent_growth
        FROM city_growth_metrics
    ''')
    rows = cur.fetchall()
    col_names = [d[0] for d in cur.description]

    if not rows:
        conn.close()
        print("[MarketDiscovery] No city growth metrics available.")
        return {'new_markets': 0, 'scored': 0}

    metrics = [dict(zip(col_names, r)) for r in rows]

    # Get existing market cities to exclude
    cur.execute('SELECT city, state FROM markets')
    existing = set((r[0], r[1]) for r in cur.fetchall())

    new_markets = 0
    scored = 0

    for m in metrics:
        city = m.get('city')
        state = m.get('state')
        if not city or not state:
            continue

        market_score = score_market(
            city, state,
            population_growth=m.get('population_growth') or 0,
            permit_growth=m.get('permit_growth') or 0,
            rent_growth=m.get('rent_growth') or 0,
        )
        scored += 1

        if market_score < 70:
            continue

        if (city, state) in existing:
            # Update score for existing markets
            try:
                cur.execute('''
                    UPDATE markets
                    SET market_score = ?, population_growth = ?,
                        permit_growth = ?, rent_growth = ?, population = ?
                    WHERE city = ? AND state = ?
                ''', (market_score, m.get('population_growth'),
                      m.get('permit_growth'), m.get('rent_growth'),
                      m.get('population'), city, state))
            except Exception:
                pass
            continue

        # Insert new market
        try:
            cur.execute('''
                INSERT INTO markets
                (id, city, state, population, population_growth, permit_growth,
                 rent_growth, market_score, collectors_active, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, CURRENT_TIMESTAMP)
            ''', (
                str(uuid.uuid4()), city, state,
                m.get('population'),
                m.get('population_growth'),
                m.get('permit_growth'),
                m.get('rent_growth'),
                market_score,
            ))

            # Log the discovery
            cur.execute('''
                INSERT INTO market_expansion_log
                (id, city, state, action, market_score, details, created_at)
                VALUES (?, ?, ?, 'MARKET_DISCOVERED', ?, ?, CURRENT_TIMESTAMP)
            ''', (
                str(uuid.uuid4()), city, state, market_score,
                json.dumps({
                    'population_growth': m.get('population_growth'),
                    'permit_growth': m.get('permit_growth'),
                    'rent_growth': m.get('rent_growth'),
                }, default=str),
            ))

            new_markets += 1
            existing.add((city, state))
            print(f"[MarketDiscovery] New market: {city}, {state} (score={market_score})")
        except Exception as e:
            print(f"[MarketDiscovery] Error inserting {city}, {state}: {e}")

    conn.commit()
    conn.close()

    print(f"\n[MarketDiscovery] COMPLETE — scored {scored} cities, {new_markets} new markets added")
    return {'new_markets': new_markets, 'scored': scored}
