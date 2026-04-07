"""
City Expansion Engine.
Detects markets with increasing development signals and
automatically deploys new collectors for those cities.
"""
import uuid
from datetime import datetime

from db import get_db
from shared.config import TARGET_CITIES


# Threshold for auto-deploying collectors to a new city
EXPANSION_THRESHOLD = 0.4  # acceleration ratio
MIN_SIGNALS_FOR_EXPANSION = 5


def detect_expansion_candidates():
    """
    Find cities with high market acceleration that are NOT yet in TARGET_CITIES.
    These are candidates for collector deployment.
    """
    conn = get_db()
    cur = conn.cursor()

    existing_cities = {(m['city'].upper(), m['state'].upper()) for m in TARGET_CITIES}

    # Get emerging markets from market_acceleration
    cur.execute('''
        SELECT city, state, acceleration_ratio, signals_90_days, signals_12_months
        FROM market_acceleration
        WHERE is_emerging = 1
        ORDER BY acceleration_ratio DESC
    ''')
    rows = cur.fetchall()

    # Also check for cities appearing in property_signals that aren't tracked
    cur.execute('''
        SELECT city, state, COUNT(*) as signal_count
        FROM property_signals
        WHERE city IS NOT NULL AND city != ''
        GROUP BY city, state
        HAVING signal_count >= ?
        ORDER BY signal_count DESC
    ''', (MIN_SIGNALS_FOR_EXPANSION,))
    untracked = cur.fetchall()

    candidates = []

    # From market acceleration
    for city, state, ratio, s90, s12 in rows:
        key = (city.upper(), state.upper())
        if key not in existing_cities:
            candidates.append({
                'city': city,
                'state': state,
                'reason': 'market_acceleration',
                'acceleration_ratio': ratio,
                'signals_90d': s90,
                'signals_12m': s12,
            })

    # From untracked signal accumulation
    for city, state, count in untracked:
        key = (city.upper(), state.upper())
        if key not in existing_cities:
            already_candidate = any(
                c['city'].upper() == city.upper() and c['state'].upper() == state.upper()
                for c in candidates
            )
            if not already_candidate:
                candidates.append({
                    'city': city,
                    'state': state,
                    'reason': 'signal_accumulation',
                    'signal_count': count,
                })

    conn.close()
    return candidates


def deploy_collectors_for_city(city, state):
    """
    Register a new city for collection by adding it to the
    collector_deployment table and scheduling collector runs.
    """
    conn = get_db()
    cur = conn.cursor()

    try:
        # Check if already deployed
        cur.execute('''
            SELECT id FROM collector_deployments
            WHERE city = ? AND state = ? AND active = 1
        ''', (city, state))
        if cur.fetchone():
            conn.close()
            return False

        cur.execute('''
            INSERT INTO collector_deployments
            (id, city, state, active, deployed_at, created_at)
            VALUES (?, ?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        ''', (str(uuid.uuid4()), city, state))
        conn.commit()
        conn.close()

        print(f"[CityExpansion] Deployed collectors for {city}, {state}")
        return True

    except Exception:
        # Table might not exist yet, create it
        try:
            cur.execute('''
                CREATE TABLE IF NOT EXISTS collector_deployments (
                    id TEXT PRIMARY KEY,
                    city TEXT NOT NULL,
                    state TEXT NOT NULL,
                    active INTEGER DEFAULT 1,
                    deployed_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            cur.execute('''
                INSERT INTO collector_deployments
                (id, city, state, active, deployed_at, created_at)
                VALUES (?, ?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ''', (str(uuid.uuid4()), city, state))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"[CityExpansion] Deploy error: {e}")
            conn.close()
            return False


def run_city_expansion():
    """
    Full expansion cycle:
    1. Detect markets with rising signals
    2. Deploy collectors for qualifying cities
    3. Emit intelligence events
    """
    print(f"[CityExpansion] START — {datetime.utcnow().isoformat()}")

    candidates = detect_expansion_candidates()
    deployed = 0

    for candidate in candidates:
        city = candidate['city']
        state = candidate['state']

        if deploy_collectors_for_city(city, state):
            deployed += 1

            # Emit intelligence event
            try:
                from app import log_intelligence_event
                reason = candidate.get('reason', 'signal_accumulation')
                ratio = candidate.get('acceleration_ratio', 0)
                log_intelligence_event(
                    event_type='CITY_EXPANSION',
                    title=f"New market deployed — {city}, {state}",
                    description=(
                        f"Collectors deployed for {city}, {state}. "
                        f"Reason: {reason}"
                        f"{f' (acceleration: {ratio:.2f}x)' if ratio else ''}"
                    ),
                    city=city,
                    state=state,
                )
            except Exception:
                pass

    print(f"[CityExpansion] COMPLETE — {deployed} new cities deployed "
          f"from {len(candidates)} candidates")
    return {
        'candidates': len(candidates),
        'deployed': deployed,
        'cities': [c['city'] for c in candidates],
    }
