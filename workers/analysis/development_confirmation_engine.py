"""
Development Confirmation Engine.
Detects when predicted parcels eventually become real developments
by cross-referencing signals: building permits, construction activity,
and multiple signals converging on the same parcel.

When confirmed, updates signal_performance.confirmed_development = TRUE.
Runs every 24 hours.
"""
import uuid
from datetime import datetime

from db import get_db


def run_development_confirmation():
    """
    Main entry point: scan signal_performance records and mark
    confirmed developments based on corroborating evidence.
    Returns dict with confirmation stats.
    """
    print(f"[DevConfirmation] START — {datetime.utcnow().isoformat()}")

    conn = get_db()
    cur = conn.cursor()

    _ensure_tables(cur, conn)

    confirmed_count = 0

    # Strategy 1: Parcels with building permits filed
    confirmed_count += _confirm_by_permits(cur)

    # Strategy 2: Parcels with construction activity signals
    confirmed_count += _confirm_by_construction(cur)

    # Strategy 3: Parcels with multiple signals from different sources
    confirmed_count += _confirm_by_signal_density(cur)

    # Strategy 4: Cross-reference with development_events
    confirmed_count += _confirm_by_development_events(cur)

    conn.commit()
    conn.close()

    print(f"[DevConfirmation] COMPLETE — {confirmed_count} developments confirmed")
    return {'confirmed': confirmed_count}


def _ensure_tables(cur, conn):
    """Create signal_performance table if missing (dev/SQLite mode)."""
    try:
        cur.execute("SELECT 1 FROM signal_performance LIMIT 1")
    except Exception:
        conn.rollback()
        cur.execute('''
            CREATE TABLE IF NOT EXISTS signal_performance (
                id TEXT PRIMARY KEY,
                signal_id TEXT,
                source_name TEXT,
                signal_type TEXT,
                parcel_id TEXT,
                predicted_development INTEGER DEFAULT 0,
                confirmed_development INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()


def _confirm_by_permits(cur):
    """
    If a parcel in signal_performance has a building permit in
    development_events, mark it confirmed.
    """
    confirmed = 0
    try:
        cur.execute('''
            SELECT sp.id, sp.parcel_id
            FROM signal_performance sp
            WHERE sp.confirmed_development = FALSE
              AND sp.parcel_id IS NOT NULL
              AND EXISTS (
                  SELECT 1 FROM development_events de
                  WHERE de.parcel_id = sp.parcel_id
                    AND de.event_type IN (
                        'BUILDING_PERMIT', 'PERMIT_FILED', 'PERMIT_APPROVED',
                        'CONSTRUCTION_PERMIT'
                    )
              )
        ''')
        rows = cur.fetchall()
        for row in rows:
            sp_id = row[0]
            cur.execute('''
                UPDATE signal_performance
                SET confirmed_development = TRUE
                WHERE id = ?
            ''', (sp_id,))
            confirmed += 1
    except Exception as e:
        print(f"[DevConfirmation] Permit confirmation error: {e}")
    return confirmed


def _confirm_by_construction(cur):
    """
    If a parcel has construction-related events, mark confirmed.
    """
    confirmed = 0
    try:
        cur.execute('''
            SELECT sp.id, sp.parcel_id
            FROM signal_performance sp
            WHERE sp.confirmed_development = FALSE
              AND sp.parcel_id IS NOT NULL
              AND EXISTS (
                  SELECT 1 FROM development_events de
                  WHERE de.parcel_id = sp.parcel_id
                    AND de.event_type IN (
                        'CONSTRUCTION_START', 'SITE_PREP', 'GRADING_PERMIT',
                        'UTILITY_CONNECTION', 'FOUNDATION_PERMIT'
                    )
              )
        ''')
        rows = cur.fetchall()
        for row in rows:
            sp_id = row[0]
            cur.execute('''
                UPDATE signal_performance
                SET confirmed_development = TRUE
                WHERE id = ?
            ''', (sp_id,))
            confirmed += 1
    except Exception as e:
        print(f"[DevConfirmation] Construction confirmation error: {e}")
    return confirmed


def _confirm_by_signal_density(cur):
    """
    If a parcel has 3+ distinct signals from different sources,
    treat it as a confirmed development.
    """
    confirmed = 0
    try:
        cur.execute('''
            SELECT sp.parcel_id, COUNT(DISTINCT sp.source_name) as source_count
            FROM signal_performance sp
            WHERE sp.confirmed_development = FALSE
              AND sp.parcel_id IS NOT NULL
            GROUP BY sp.parcel_id
            HAVING COUNT(DISTINCT sp.source_name) >= 3
        ''')
        parcels = cur.fetchall()
        for row in parcels:
            parcel_id = row[0]
            cur.execute('''
                UPDATE signal_performance
                SET confirmed_development = TRUE
                WHERE parcel_id = ? AND confirmed_development = FALSE
            ''', (parcel_id,))
            confirmed += cur.rowcount
    except Exception as e:
        print(f"[DevConfirmation] Signal density confirmation error: {e}")
    return confirmed


def _confirm_by_development_events(cur):
    """
    Cross-reference unconfirmed signals with development_events
    for the same city/developer combination.
    """
    confirmed = 0
    try:
        # Match signals to confirmed development events by city
        cur.execute('''
            SELECT sp.id
            FROM signal_performance sp
            JOIN signal_sources ss ON ss.source_name = sp.source_name
            WHERE sp.confirmed_development = FALSE
              AND ss.city IS NOT NULL
              AND EXISTS (
                  SELECT 1 FROM development_events de
                  WHERE de.city = ss.city
                    AND de.event_type IN (
                        'CONSTRUCTION_START', 'BUILDING_PERMIT',
                        'PERMIT_APPROVED', 'PROJECT_ANNOUNCED'
                    )
              )
        ''')
        rows = cur.fetchall()
        for row in rows:
            cur.execute('''
                UPDATE signal_performance
                SET confirmed_development = TRUE
                WHERE id = ?
            ''', (row[0],))
            confirmed += 1
    except Exception as e:
        print(f"[DevConfirmation] Dev events confirmation error: {e}")
    return confirmed


def run_development_confirmation_worker():
    """Worker wrapper for scheduler/pipeline integration."""
    try:
        result = run_development_confirmation()
        print(f"[DevConfirmation Worker] Result: {result}")
        return result
    except Exception as e:
        print(f"[DevConfirmation Worker] Error: {e}")
        import traceback
        traceback.print_exc()
        return {'confirmed': 0, 'error': str(e)}
