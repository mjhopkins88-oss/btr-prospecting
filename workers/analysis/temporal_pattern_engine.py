"""
Temporal Development Pattern Engine.
Detects signal sequences that historically precede development.

Example pattern:
  ENGINEERING_ENGAGEMENT → ZONING_APPLICATION → BUILDING_PERMIT
  within 120 days → high probability of active development.
"""
import json
import uuid
from datetime import datetime, timedelta

from db import get_db


# Known temporal patterns that signal development progression
DEVELOPMENT_PATTERNS = [
    {
        'name': 'classic_development_sequence',
        'signals': ['ENGINEERING_ENGAGEMENT', 'ZONING_APPLICATION', 'BUILDING_PERMIT'],
        'window_days': 120,
        'confidence': 90,
        'description': 'Engineering → Zoning → Permit within 120 days',
    },
    {
        'name': 'land_to_permit_fast',
        'signals': ['LAND_PURCHASE', 'ZONING_APPLICATION', 'SITE_PLAN_SUBMISSION'],
        'window_days': 180,
        'confidence': 85,
        'description': 'Land purchase → Zoning → Site plan within 180 days',
    },
    {
        'name': 'llc_to_development',
        'signals': ['LLC_FORMATION', 'LAND_PURCHASE', 'ENGINEERING_ENGAGEMENT'],
        'window_days': 240,
        'confidence': 80,
        'description': 'LLC formation → Land purchase → Engineering within 240 days',
    },
    {
        'name': 'engineering_to_utility',
        'signals': ['ENGINEERING_ENGAGEMENT', 'UTILITY_APPLICATION'],
        'window_days': 90,
        'confidence': 75,
        'description': 'Engineering engagement → Utility application within 90 days',
    },
    {
        'name': 'rapid_permit_progression',
        'signals': ['SITE_PLAN_SUBMISSION', 'BUILDING_PERMIT'],
        'window_days': 60,
        'confidence': 85,
        'description': 'Site plan → Building permit within 60 days',
    },
    {
        'name': 'developer_expansion_pattern',
        'signals': ['DEVELOPER_EXPANSION', 'LLC_FORMATION', 'LAND_PURCHASE'],
        'window_days': 365,
        'confidence': 70,
        'description': 'Developer expansion → LLC → Land purchase within 1 year',
    },
]


def detect_temporal_patterns():
    """
    Scan property_signals for signal sequences matching known patterns.
    Creates pattern match records and emits intelligence events.
    """
    conn = get_db()
    cur = conn.cursor()

    # Get all parcels with signals, grouped by parcel
    cur.execute('''
        SELECT parcel_id, signal_type, created_at
        FROM property_signals
        WHERE parcel_id IS NOT NULL AND parcel_id != ''
        ORDER BY parcel_id, created_at ASC
    ''')
    rows = cur.fetchall()

    # Group signals by parcel
    parcel_signals = {}
    for parcel_id, signal_type, created_at in rows:
        parcel_signals.setdefault(parcel_id, []).append({
            'type': signal_type,
            'date': created_at,
        })

    matches_created = 0

    for parcel_id, signals in parcel_signals.items():
        signal_types = set(s['type'] for s in signals)
        signal_dates = [s['date'] for s in signals if s['date']]

        for pattern in DEVELOPMENT_PATTERNS:
            required = pattern['signals']

            # Check if all required signal types are present
            if not all(s in signal_types for s in required):
                continue

            # Check time window
            if len(signal_dates) >= 2:
                try:
                    first = _parse_date(signal_dates[0])
                    last = _parse_date(signal_dates[-1])
                    if first and last:
                        window = (last - first).days
                        if window > pattern['window_days']:
                            continue
                    else:
                        window = 0
                except Exception:
                    window = 0
            else:
                window = 0

            # Check if match already exists
            pattern_name = pattern['name']
            cur.execute('''
                SELECT id FROM pattern_matches
                WHERE parcel_id = ? AND pattern_id = ?
            ''', (parcel_id, pattern_name))
            if cur.fetchone():
                continue

            # Create pattern match
            match_id = str(uuid.uuid4())
            confidence = pattern['confidence']

            # Boost confidence if signals arrived in expected order
            ordered_types = [s['type'] for s in signals]
            if _check_order(ordered_types, required):
                confidence = min(confidence + 5, 100)

            try:
                cur.execute('''
                    INSERT INTO pattern_matches
                    (id, parcel_id, pattern_id, match_confidence,
                     signals_detected, first_signal_date, last_signal_date, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ''', (
                    match_id, parcel_id, pattern_name, confidence,
                    len(signals),
                    str(signal_dates[0]) if signal_dates else None,
                    str(signal_dates[-1]) if signal_dates else None,
                ))

                # Log to pattern engine log
                cur.execute('''
                    INSERT INTO pattern_engine_log
                    (id, parcel_id, pattern_id, detection_time, confidence, notes)
                    VALUES (?, ?, ?, CURRENT_TIMESTAMP, ?, ?)
                ''', (
                    str(uuid.uuid4()), parcel_id, pattern_name, confidence,
                    f"Temporal pattern '{pattern['description']}' detected "
                    f"with {len(signals)} signals",
                ))

                matches_created += 1
                print(f"[TemporalPatterns] Match: parcel={parcel_id} "
                      f"pattern={pattern_name} confidence={confidence}")

                # Emit intelligence event
                _emit_pattern_event(parcel_id, pattern, confidence, cur)

            except Exception as e:
                print(f"[TemporalPatterns] Error storing match: {e}")

    conn.commit()
    conn.close()
    print(f"[TemporalPatterns] Created {matches_created} new pattern matches")
    return {'matches_created': matches_created}


def _check_order(actual_types, expected_order):
    """Check if expected signals appear in the correct order within actual."""
    positions = []
    for expected in expected_order:
        for i, actual in enumerate(actual_types):
            if actual == expected:
                positions.append(i)
                break
    # Check if positions are monotonically increasing
    return all(positions[i] < positions[i+1] for i in range(len(positions)-1)) if len(positions) == len(expected_order) else False


def _parse_date(date_str):
    """Parse various date formats."""
    if not date_str:
        return None
    if isinstance(date_str, datetime):
        return date_str
    for fmt in ('%Y-%m-%dT%H:%M:%S', '%Y-%m-%d', '%Y-%m-%dT%H:%M:%S.%f'):
        try:
            return datetime.strptime(str(date_str).replace('Z', ''), fmt)
        except ValueError:
            continue
    return None


def _emit_pattern_event(parcel_id, pattern, confidence, cur):
    """Emit intelligence event for pattern detection."""
    try:
        # Get parcel location
        cur.execute('SELECT city, state FROM parcels WHERE parcel_id = ?', (parcel_id,))
        row = cur.fetchone()
        city = row[0] if row else 'Unknown'
        state = row[1] if row else ''

        from app import log_intelligence_event
        log_intelligence_event(
            event_type='TEMPORAL_PATTERN',
            title=f"Development pattern detected — {city}, {state}",
            description=f"{pattern['description']} (confidence: {confidence}%)",
            city=city,
            state=state,
            related_entity=parcel_id,
            entity_id=parcel_id,
        )
    except Exception:
        pass


def run_temporal_engine():
    """Full temporal pattern detection cycle."""
    print(f"[TemporalPatterns] START — {datetime.utcnow().isoformat()}")
    result = detect_temporal_patterns()
    print(f"[TemporalPatterns] COMPLETE")
    return result
