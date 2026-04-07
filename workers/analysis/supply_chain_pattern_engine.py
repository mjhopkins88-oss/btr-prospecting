"""
Supply Chain Pattern Detection Engine.
Detects construction supply chain signal sequences that indicate
imminent development activity.

Key patterns:
  CIVIL_ENGINEERING_PLAN → SITE_PREP_ACTIVITY → UTILITY_CONNECTION_REQUEST
  within 120 days = high probability of active construction.

  ENGINEERING_ENGAGEMENT → EARTHWORK_CONTRACTOR → CONCRETE_SUPPLY_SIGNAL
  within 90 days = construction starting.
"""
import json
import uuid
from datetime import datetime, timedelta

from db import get_db


# Supply chain patterns that indicate construction progression
SUPPLY_CHAIN_PATTERNS = [
    {
        'name': 'full_supply_chain_sequence',
        'signals': ['CIVIL_ENGINEERING_PLAN', 'SITE_PREP_ACTIVITY', 'UTILITY_CONNECTION_REQUEST'],
        'window_days': 120,
        'confidence': 90,
        'probability_boost': 25,
        'description': 'Engineering plan → Site prep → Utility request within 120 days',
    },
    {
        'name': 'engineering_to_construction',
        'signals': ['ENGINEERING_ENGAGEMENT', 'EARTHWORK_CONTRACTOR', 'CONCRETE_SUPPLY_SIGNAL'],
        'window_days': 90,
        'confidence': 88,
        'probability_boost': 25,
        'description': 'Engineering → Earthwork → Concrete within 90 days',
    },
    {
        'name': 'site_prep_to_utility',
        'signals': ['SITE_PREP_ACTIVITY', 'UTILITY_CONNECTION_REQUEST'],
        'window_days': 60,
        'confidence': 82,
        'probability_boost': 20,
        'description': 'Site prep → Utility connection within 60 days',
    },
    {
        'name': 'engineering_to_site_prep',
        'signals': ['CIVIL_ENGINEERING_PLAN', 'SITE_PREP_ACTIVITY'],
        'window_days': 90,
        'confidence': 80,
        'probability_boost': 20,
        'description': 'Engineering plan → Site prep within 90 days',
    },
    {
        'name': 'contractor_to_infrastructure',
        'signals': ['EARTHWORK_CONTRACTOR', 'INFRASTRUCTURE_BID'],
        'window_days': 60,
        'confidence': 78,
        'probability_boost': 15,
        'description': 'Earthwork → Infrastructure bid within 60 days',
    },
    {
        'name': 'rapid_construction_start',
        'signals': ['SITE_PREP_ACTIVITY', 'CONCRETE_SUPPLY_SIGNAL'],
        'window_days': 45,
        'confidence': 85,
        'probability_boost': 22,
        'description': 'Site prep → Concrete supply within 45 days',
    },
    {
        'name': 'engineering_full_pipeline',
        'signals': ['CIVIL_ENGINEERING_PLAN', 'EARTHWORK_CONTRACTOR',
                     'SITE_PREP_ACTIVITY', 'UTILITY_CONNECTION_REQUEST'],
        'window_days': 180,
        'confidence': 95,
        'probability_boost': 30,
        'description': 'Full construction pipeline: eng → earth → site prep → utility',
    },
]


def detect_supply_chain_patterns():
    """
    Scan property_signals for construction supply chain patterns.
    Creates pattern matches and boosts development probability.
    """
    conn = get_db()
    cur = conn.cursor()

    # Get all parcels with supply chain signals
    supply_chain_types = (
        'CIVIL_ENGINEERING_PLAN', 'SITE_PREP_ACTIVITY',
        'UTILITY_CONNECTION_REQUEST', 'EARTHWORK_CONTRACTOR',
        'CONCRETE_SUPPLY_SIGNAL', 'INFRASTRUCTURE_BID',
        'ENGINEERING_ENGAGEMENT',
    )
    placeholders = ','.join(['?' for _ in supply_chain_types])

    cur.execute(f'''
        SELECT parcel_id, signal_type, created_at
        FROM property_signals
        WHERE parcel_id IS NOT NULL AND parcel_id != ''
        AND signal_type IN ({placeholders})
        ORDER BY parcel_id, created_at ASC
    ''', supply_chain_types)
    rows = cur.fetchall()

    # Group signals by parcel
    parcel_signals = {}
    for parcel_id, signal_type, created_at in rows:
        parcel_signals.setdefault(parcel_id, []).append({
            'type': signal_type,
            'date': created_at,
        })

    matches_created = 0
    parcels_boosted = 0

    for parcel_id, signals in parcel_signals.items():
        signal_types = set(s['type'] for s in signals)
        signal_dates = [s['date'] for s in signals if s['date']]

        for pattern in SUPPLY_CHAIN_PATTERNS:
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
                except Exception:
                    pass

            # Check if match already exists
            pattern_name = f"supply_chain_{pattern['name']}"
            cur.execute('''
                SELECT id FROM pattern_matches
                WHERE parcel_id = ? AND pattern_id = ?
            ''', (parcel_id, pattern_name))
            if cur.fetchone():
                continue

            # Create pattern match
            match_id = str(uuid.uuid4())
            confidence = pattern['confidence']

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

                # Log detection
                cur.execute('''
                    INSERT INTO pattern_engine_log
                    (id, parcel_id, pattern_id, detection_time, confidence, notes)
                    VALUES (?, ?, ?, CURRENT_TIMESTAMP, ?, ?)
                ''', (
                    str(uuid.uuid4()), parcel_id, pattern_name, confidence,
                    f"Supply chain pattern '{pattern['description']}' with {len(signals)} signals",
                ))

                matches_created += 1
                print(f"[SupplyChainPatterns] Match: parcel={parcel_id} "
                      f"pattern={pattern['name']} confidence={confidence}")

                # Boost development probability
                boost = pattern['probability_boost']
                cur.execute('''
                    UPDATE parcels
                    SET development_probability = MIN(
                        COALESCE(development_probability, 0) + ?, 100
                    )
                    WHERE parcel_id = ?
                ''', (boost, parcel_id))
                parcels_boosted += 1

                # Emit intelligence event
                _emit_supply_chain_event(cur, parcel_id, pattern, confidence)

            except Exception as e:
                print(f"[SupplyChainPatterns] Error: {e}")

    conn.commit()
    conn.close()
    print(f"[SupplyChainPatterns] Created {matches_created} matches, "
          f"boosted {parcels_boosted} parcels")
    return {
        'matches_created': matches_created,
        'parcels_boosted': parcels_boosted,
    }


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


def _emit_supply_chain_event(cur, parcel_id, pattern, confidence):
    """Emit intelligence event for supply chain pattern detection."""
    try:
        cur.execute('SELECT city, state FROM parcels WHERE parcel_id = ?', (parcel_id,))
        row = cur.fetchone()
        city = row[0] if row else 'Unknown'
        state = row[1] if row else ''

        from app import log_intelligence_event
        log_intelligence_event(
            event_type='SUPPLY_CHAIN',
            title=f"Construction supply chain pattern — {city}, {state}",
            description=(
                f"{pattern['description']} (confidence: {confidence}%)"
            ),
            city=city,
            state=state,
            related_entity=parcel_id,
            entity_id=parcel_id,
        )
    except Exception:
        pass


def run_supply_chain_engine():
    """Full supply chain pattern detection cycle."""
    print(f"[SupplyChainPatterns] START — {datetime.utcnow().isoformat()}")
    result = detect_supply_chain_patterns()
    print(f"[SupplyChainPatterns] COMPLETE")
    return result
