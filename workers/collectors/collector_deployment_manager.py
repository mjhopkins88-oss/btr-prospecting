"""
Collector Deployment Manager.
When a new market is detected, activates signal collectors for:
- building permits
- zoning filings
- land purchases
- planning agendas
- bid boards
Updates markets.collectors_active = TRUE and creates baseline records.
"""
import uuid
import json
from datetime import datetime

from db import get_db


# Collector types to deploy per market
COLLECTOR_TYPES = [
    'building_permits',
    'zoning_filings',
    'land_purchases',
    'planning_agendas',
    'bid_boards',
]


def deploy_collectors_for_new_markets():
    """
    Find markets where collectors_active = FALSE and deploy collectors.
    Returns count of markets activated.
    """
    conn = get_db()
    cur = conn.cursor()

    cur.execute('''
        SELECT id, city, state, market_score
        FROM markets
        WHERE collectors_active = FALSE
        ORDER BY market_score DESC
    ''')
    rows = cur.fetchall()
    col_names = [d[0] for d in cur.description]

    if not rows:
        conn.close()
        print("[CollectorDeploy] No pending markets to activate.")
        return 0

    markets = [dict(zip(col_names, r)) for r in rows]
    activated = 0

    for market in markets:
        city = market['city']
        state = market['state']

        try:
            # Initialize signal monitoring for this city
            _initialize_city_signals(cur, city, state)

            # Mark collectors as active
            cur.execute('''
                UPDATE markets SET collectors_active = TRUE WHERE id = ?
            ''', (market['id'],))

            # Log deployment
            cur.execute('''
                INSERT INTO market_expansion_log
                (id, city, state, action, market_score, details, created_at)
                VALUES (?, ?, ?, 'COLLECTORS_DEPLOYED', ?, ?, CURRENT_TIMESTAMP)
            ''', (
                str(uuid.uuid4()), city, state, market['market_score'],
                json.dumps({
                    'collectors': COLLECTOR_TYPES,
                    'deployed_at': datetime.utcnow().isoformat(),
                }, default=str),
            ))

            activated += 1
            print(f"[CollectorDeploy] Activated collectors for {city}, {state}")
        except Exception as e:
            print(f"[CollectorDeploy] Error deploying to {city}, {state}: {e}")

    conn.commit()
    conn.close()
    print(f"[CollectorDeploy] Deployed collectors to {activated} new markets.")
    return activated


def _initialize_city_signals(cur, city, state):
    """
    Create baseline signal monitoring records for a new city.
    Inserts discovery_seen entries so the platform knows to scan this market.
    """
    # Add to discovery_seen as a baseline entry so existing collectors
    # will pick up this city on their next scan
    for collector_type in COLLECTOR_TYPES:
        try:
            cur.execute('''
                SELECT id FROM discovery_seen
                WHERE business_name = ? AND city = ? AND state = ?
                LIMIT 1
            ''', (f'__market_expansion_{collector_type}', city, state))
            if not cur.fetchone():
                cur.execute('''
                    INSERT INTO discovery_seen
                    (business_name, city, state, category, icp_keyword, first_seen)
                    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ''', (
                    f'__market_expansion_{collector_type}',
                    city, state,
                    'market_expansion',
                    collector_type,
                ))
        except Exception:
            pass

    # Ensure the city is registered for government signal scanning
    # by adding a baseline development_events marker
    try:
        cur.execute('''
            SELECT id FROM development_events
            WHERE city = ? AND state = ? AND event_type = 'MARKET_ACTIVATED'
            LIMIT 1
        ''', (city, state))
        if not cur.fetchone():
            cur.execute('''
                INSERT INTO development_events
                (id, event_type, city, state, developer, event_date, source, created_at)
                VALUES (?, 'MARKET_ACTIVATED', ?, ?, NULL, ?, 'market_expansion', CURRENT_TIMESTAMP)
            ''', (str(uuid.uuid4()), city, state, datetime.utcnow().isoformat()))
    except Exception:
        pass
