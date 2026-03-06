"""
Parcel Momentum Engine.
Measures how quickly signals accumulate around parcels.
Compares recent activity (last 60 days) to historical (last 12 months)
to detect acceleration.
"""
import uuid
from datetime import datetime, timedelta

from db import get_db


def calculate_parcel_momentum():
    """
    Calculate signal momentum for all parcels.
    Momentum = signals_last_60_days / max(signals_last_12_months, 1)

    If acceleration detected (momentum > 0.5), increase development_probability.
    """
    conn = get_db()
    cur = conn.cursor()

    now = datetime.utcnow()
    cutoff_60 = (now - timedelta(days=60)).isoformat()
    cutoff_12m = (now - timedelta(days=365)).isoformat()

    # Get signal counts per parcel for both windows
    cur.execute('''
        SELECT parcel_id,
            SUM(CASE WHEN created_at >= ? THEN 1 ELSE 0 END) as signals_60d,
            SUM(CASE WHEN created_at >= ? THEN 1 ELSE 0 END) as signals_12m
        FROM property_signals
        WHERE parcel_id IS NOT NULL AND parcel_id != ''
        GROUP BY parcel_id
        HAVING signals_12m > 0
    ''', (cutoff_60, cutoff_12m))

    rows = cur.fetchall()
    boosted = 0
    high_momentum = []

    for parcel_id, signals_60d, signals_12m in rows:
        momentum = signals_60d / max(signals_12m, 1)

        # Calculate momentum boost
        boost = 0
        if momentum >= 1.0 and signals_60d >= 3:
            boost = 20  # Very high acceleration
        elif momentum >= 0.5 and signals_60d >= 2:
            boost = 15  # High acceleration
        elif momentum >= 0.3 and signals_60d >= 1:
            boost = 10  # Moderate acceleration

        if boost > 0:
            try:
                # Update parcel development probability
                cur.execute('''
                    UPDATE parcels
                    SET development_probability = MIN(
                        COALESCE(development_probability, 0) + ?, 100
                    )
                    WHERE parcel_id = ?
                ''', (boost, parcel_id))
                boosted += 1

                if momentum >= 0.5:
                    high_momentum.append({
                        'parcel_id': parcel_id,
                        'momentum': round(momentum, 2),
                        'signals_60d': signals_60d,
                        'signals_12m': signals_12m,
                        'boost': boost,
                    })
            except Exception:
                pass

    conn.commit()

    # Emit intelligence events for high-momentum parcels
    for pm in high_momentum[:10]:  # Limit to top 10
        try:
            cur2 = conn.cursor()
            cur2.execute('SELECT city, state FROM parcels WHERE parcel_id = ?',
                         (pm['parcel_id'],))
            row = cur2.fetchone()
            city = row[0] if row else 'Unknown'
            state = row[1] if row else ''
        except Exception:
            city, state = 'Unknown', ''

        try:
            from app import log_intelligence_event
            log_intelligence_event(
                event_type='PARCEL_MOMENTUM',
                title=f"Signal momentum spike — {city}, {state}",
                description=(
                    f"Parcel {pm['parcel_id'][:12]}... has {pm['signals_60d']} signals "
                    f"in last 60 days (momentum: {pm['momentum']}x)"
                ),
                city=city,
                state=state,
                related_entity=pm['parcel_id'],
                entity_id=pm['parcel_id'],
            )
        except Exception:
            pass

    conn.close()
    print(f"[MomentumEngine] Boosted {boosted} parcels, "
          f"{len(high_momentum)} high-momentum detected")
    return {
        'parcels_boosted': boosted,
        'high_momentum_count': len(high_momentum),
    }


def run_momentum_engine():
    """Full momentum calculation cycle."""
    print(f"[MomentumEngine] START — {datetime.utcnow().isoformat()}")
    result = calculate_parcel_momentum()
    print(f"[MomentumEngine] COMPLETE")
    return result
