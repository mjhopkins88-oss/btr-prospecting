"""
Market Acceleration Detection Engine.
Detects cities where development signals are spiking.
Compares signals_last_90_days to signals_last_12_months.
Flags cities as emerging development markets when ratio exceeds threshold.
"""
import uuid
from datetime import datetime, timedelta

from db import get_db


# Acceleration threshold: if 90-day signals / 12-month signals > this, flag as emerging
ACCELERATION_THRESHOLD = 0.4
# Minimum signals needed to qualify
MIN_SIGNALS_90D = 3
MIN_SIGNALS_12M = 5


def detect_market_acceleration():
    """
    Detect cities where development signals are accelerating.
    Stores results in market_acceleration table.
    """
    conn = get_db()
    cur = conn.cursor()

    now = datetime.utcnow()
    cutoff_90 = (now - timedelta(days=90)).isoformat()
    cutoff_12m = (now - timedelta(days=365)).isoformat()

    # Aggregate signals by city from property_signals
    cur.execute('''
        SELECT city, state,
            SUM(CASE WHEN created_at >= ? THEN 1 ELSE 0 END) as signals_90d,
            SUM(CASE WHEN created_at >= ? THEN 1 ELSE 0 END) as signals_12m
        FROM property_signals
        WHERE city IS NOT NULL AND city != ''
        GROUP BY city, state
    ''', (cutoff_90, cutoff_12m))

    city_signals = cur.fetchall()

    # Also count from li_signals for broader coverage
    try:
        cur.execute('''
            SELECT city, state,
                SUM(CASE WHEN created_at >= ? THEN 1 ELSE 0 END) as signals_90d,
                SUM(CASE WHEN created_at >= ? THEN 1 ELSE 0 END) as signals_12m
            FROM li_signals
            WHERE city IS NOT NULL AND city != ''
            GROUP BY city, state
        ''', (cutoff_90, cutoff_12m))
        li_signals = cur.fetchall()
    except Exception:
        li_signals = []

    # Merge counts by city
    city_totals = {}
    for city, state, s90, s12 in list(city_signals) + list(li_signals):
        key = (city, state)
        if key not in city_totals:
            city_totals[key] = {'s90': 0, 's12': 0}
        city_totals[key]['s90'] += s90 or 0
        city_totals[key]['s12'] += s12 or 0

    emerging = 0
    updated = 0

    for (city, state), counts in city_totals.items():
        s90 = counts['s90']
        s12 = counts['s12']
        ratio = s90 / max(s12, 1)
        is_emerging = (
            ratio >= ACCELERATION_THRESHOLD
            and s90 >= MIN_SIGNALS_90D
            and s12 >= MIN_SIGNALS_12M
        )

        # Upsert into market_acceleration
        try:
            cur.execute('''
                SELECT id FROM market_acceleration WHERE city = ? AND state = ?
            ''', (city, state))
            existing = cur.fetchone()

            if existing:
                cur.execute('''
                    UPDATE market_acceleration
                    SET signals_90_days = ?, signals_12_months = ?,
                        acceleration_ratio = ?, is_emerging = ?,
                        last_calculated = CURRENT_TIMESTAMP
                    WHERE city = ? AND state = ?
                ''', (s90, s12, round(ratio, 3), 1 if is_emerging else 0,
                      city, state))
            else:
                cur.execute('''
                    INSERT INTO market_acceleration
                    (id, city, state, signals_90_days, signals_12_months,
                     acceleration_ratio, is_emerging, last_calculated, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ''', (str(uuid.uuid4()), city, state, s90, s12,
                      round(ratio, 3), 1 if is_emerging else 0))

            updated += 1
            if is_emerging:
                emerging += 1
        except Exception as e:
            print(f"[MarketAccel] Error updating {city}, {state}: {e}")

    # Emit intelligence events for newly emerging markets
    if emerging > 0:
        cur.execute('''
            SELECT city, state, acceleration_ratio, signals_90_days
            FROM market_acceleration
            WHERE is_emerging = 1
            ORDER BY acceleration_ratio DESC
            LIMIT 5
        ''')
        top_emerging = cur.fetchall()
        for city, state, ratio, s90 in top_emerging:
            try:
                from app import log_intelligence_event
                log_intelligence_event(
                    event_type='MARKET_ACCELERATION',
                    title=f"Emerging market detected — {city}, {state}",
                    description=(
                        f"Signal acceleration ratio: {ratio:.2f}x "
                        f"({s90} signals in last 90 days)"
                    ),
                    city=city,
                    state=state,
                )
            except Exception:
                pass

    conn.commit()
    conn.close()
    print(f"[MarketAccel] Updated {updated} markets, {emerging} emerging")
    return {'markets_updated': updated, 'emerging_markets': emerging}


def get_emerging_markets():
    """Return list of currently emerging markets."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute('''
        SELECT city, state, acceleration_ratio, signals_90_days, signals_12_months
        FROM market_acceleration
        WHERE is_emerging = 1
        ORDER BY acceleration_ratio DESC
    ''')
    rows = cur.fetchall()
    cols = [d[0] for d in cur.description]
    conn.close()
    return [dict(zip(cols, r)) for r in rows]


def run_market_acceleration():
    """Full market acceleration detection cycle."""
    print(f"[MarketAccel] START — {datetime.utcnow().isoformat()}")
    result = detect_market_acceleration()
    print(f"[MarketAccel] COMPLETE")
    return result
