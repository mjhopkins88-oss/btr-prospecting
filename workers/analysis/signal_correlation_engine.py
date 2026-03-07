"""
Signal Correlation Engine.
Identifies sequences of signals that strongly indicate development.

Example high-confidence sequence:
  DEVELOPMENT_ENTITY_FORMATION
  → LAND_PURCHASE / DEED_TRANSFER
  → SITE_PLAN_SUBMISSION / CIVIL_ENGINEERING_PLAN
  → UTILITY_CONNECTION_REQUEST
  → SUBDIVISION_PLAT / FINAL_PLAT

If this sequence appears within 6–12 months, development probability
is boosted significantly.
"""
import json
import uuid
from collections import defaultdict
from datetime import datetime, timedelta

from db import get_db


# Signal sequence patterns that indicate high-probability development
DEVELOPMENT_SEQUENCES = [
    {
        'name': 'full_development_pipeline',
        'signals': [
            ['DEVELOPMENT_ENTITY_FORMATION', 'LLC_FORMATION'],
            ['LAND_PURCHASE', 'DEED_TRANSFER', 'OWNER_CHANGE', 'DEVELOPMENT_LAND_LISTING'],
            ['SITE_PLAN_SUBMISSION', 'CIVIL_ENGINEERING_PLAN', 'GRADING_PLAN', 'ENGINEERING_REVIEW'],
            ['UTILITY_CONNECTION_REQUEST', 'UTILITY_CAPACITY_EXPANSION', 'NEW_SERVICE_APPLICATION'],
            ['SUBDIVISION_PLAT', 'PRELIMINARY_PLAT', 'FINAL_PLAT'],
        ],
        'min_stages': 3,
        'boost': 30,
        'window_days': 365,
    },
    {
        'name': 'engineering_to_permit',
        'signals': [
            ['SITE_PLAN_SUBMISSION', 'CIVIL_ENGINEERING_PLAN', 'ENGINEERING_REVIEW'],
            ['UTILITY_CONNECTION_REQUEST', 'NEW_SERVICE_APPLICATION'],
            ['BUILDING_PERMIT', 'MULTIFAMILY_PERMIT', 'SUBDIVISION_PERMIT'],
        ],
        'min_stages': 2,
        'boost': 20,
        'window_days': 270,
    },
    {
        'name': 'entity_to_land_acquisition',
        'signals': [
            ['DEVELOPMENT_ENTITY_FORMATION', 'LLC_FORMATION'],
            ['LAND_PURCHASE', 'DEED_TRANSFER', 'DEVELOPMENT_LAND_LISTING'],
            ['ZONING_APPLICATION', 'REZONING_REQUEST', 'ZONING_AGENDA_ITEM'],
        ],
        'min_stages': 2,
        'boost': 15,
        'window_days': 365,
    },
    {
        'name': 'infrastructure_to_construction',
        'signals': [
            ['TRAFFIC_IMPACT_STUDY', 'ROAD_EXPANSION_APPROVAL', 'INFRASTRUCTURE_EXTENSION'],
            ['GRADING_PLAN', 'SITE_PREP_ACTIVITY'],
            ['CONSTRUCTION_FINANCING', 'COMMERCIAL_MORTGAGE'],
            ['BUILDING_PERMIT', 'MULTIFAMILY_PERMIT'],
        ],
        'min_stages': 2,
        'boost': 20,
        'window_days': 365,
    },
    {
        'name': 'builder_expansion',
        'signals': [
            ['BUILDER_EXPANSION_PATTERN'],
            ['DEVELOPMENT_LAND_LISTING', 'LAND_PURCHASE'],
            ['CONSTRUCTION_HIRING_SIGNAL'],
        ],
        'min_stages': 2,
        'boost': 15,
        'window_days': 180,
    },
]


def _get_signals_by_location():
    """Fetch recent signals grouped by location (city+state or parcel)."""
    conn = get_db()
    cur = conn.cursor()

    cutoff = (datetime.utcnow() - timedelta(days=365)).isoformat()

    cur.execute('''
        SELECT signal_type, entity_name, city, state, parcel_id,
               created_at, metadata
        FROM property_signals
        WHERE created_at >= ?
        ORDER BY created_at ASC
    ''', (cutoff,))

    rows = cur.fetchall()
    conn.close()

    # Group by location key (parcel_id if available, else city+state+entity)
    location_signals = defaultdict(list)
    for signal_type, entity_name, city, state, parcel_id, created_at, metadata in rows:
        # Primary key: parcel_id
        if parcel_id:
            location_signals[f"parcel:{parcel_id}"].append({
                'signal_type': signal_type,
                'entity_name': entity_name,
                'city': city,
                'state': state,
                'parcel_id': parcel_id,
                'created_at': created_at,
            })
        # Secondary key: entity_name + city + state
        if entity_name and city and state:
            key = f"entity:{entity_name.upper().strip()}|{city}|{state}"
            location_signals[key].append({
                'signal_type': signal_type,
                'entity_name': entity_name,
                'city': city,
                'state': state,
                'parcel_id': parcel_id,
                'created_at': created_at,
            })

    return location_signals


def _check_sequence(signals, sequence_def):
    """Check if a set of signals matches a development sequence pattern."""
    window_days = sequence_def['window_days']
    stages = sequence_def['signals']
    min_stages = sequence_def['min_stages']

    # Parse dates and sort
    dated_signals = []
    for s in signals:
        try:
            dt = datetime.fromisoformat(s['created_at'].replace('Z', '+00:00').replace('+00:00', ''))
        except (ValueError, AttributeError):
            try:
                dt = datetime.strptime(s['created_at'][:19], '%Y-%m-%d %H:%M:%S')
            except (ValueError, AttributeError):
                continue
        dated_signals.append((dt, s['signal_type']))

    if not dated_signals:
        return None

    dated_signals.sort(key=lambda x: x[0])

    # Check time window
    time_span = (dated_signals[-1][0] - dated_signals[0][0]).days
    if time_span > window_days:
        return None

    # Check how many stages are matched
    signal_types_present = {st for _, st in dated_signals}
    matched_stages = 0
    matched_stage_names = []

    for stage_options in stages:
        if signal_types_present & set(stage_options):
            matched_stages += 1
            matched = signal_types_present & set(stage_options)
            matched_stage_names.append(list(matched)[0])

    if matched_stages >= min_stages:
        return {
            'sequence_name': sequence_def['name'],
            'stages_matched': matched_stages,
            'total_stages': len(stages),
            'matched_signals': matched_stage_names,
            'boost': sequence_def['boost'],
            'time_span_days': time_span,
        }

    return None


def _store_correlation_results(correlations):
    """Store correlation results and boost development probability."""
    conn = get_db()
    cur = conn.cursor()
    stored = 0
    boosted_parcels = set()

    for corr in correlations:
        sig_id = str(uuid.uuid4())
        metadata = {
            'source_collector': 'signal_correlation_engine',
            'sequence_name': corr['sequence_name'],
            'stages_matched': corr['stages_matched'],
            'total_stages': corr['total_stages'],
            'matched_signals': corr['matched_signals'],
            'time_span_days': corr['time_span_days'],
            'location_key': corr['location_key'],
        }

        city = corr.get('city')
        state = corr.get('state')
        parcel_id = corr.get('parcel_id')
        entity_name = corr.get('entity_name')

        try:
            cur.execute('''
                INSERT OR IGNORE INTO property_signals
                (id, signal_type, source, entity_name, city, state,
                 parcel_id, metadata, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                sig_id, 'SIGNAL_SEQUENCE_MATCH', 'signal_correlation_engine',
                entity_name, city, state, parcel_id,
                json.dumps(metadata, default=str),
            ))
            stored += 1
        except Exception:
            pass

        # Boost development probability
        boost = corr['boost']
        if parcel_id and parcel_id not in boosted_parcels:
            try:
                cur.execute('''
                    UPDATE parcels SET development_probability = MIN(
                        COALESCE(development_probability, 0) + ?, 100
                    ) WHERE parcel_id = ?
                ''', (boost, parcel_id))
                boosted_parcels.add(parcel_id)
            except Exception:
                pass
        elif city and state:
            try:
                cur.execute('''
                    UPDATE parcels SET development_probability = MIN(
                        COALESCE(development_probability, 0) + ?, 100
                    ) WHERE city = ? AND state = ?
                    AND parcel_id IS NOT NULL
                    AND parcel_id NOT IN ({})
                '''.format(','.join('?' * len(boosted_parcels)) if boosted_parcels else "''"),
                    (boost, city, state, *boosted_parcels) if boosted_parcels else (boost, city, state))
            except Exception:
                pass

    conn.commit()
    conn.close()
    return stored, len(boosted_parcels)


def run_signal_correlation():
    """Main entry point: detect signal sequence correlations."""
    print(f"[SignalCorrelationEngine] START — {datetime.utcnow().isoformat()}")

    location_signals = _get_signals_by_location()
    print(f"[SignalCorrelationEngine] Analyzing {len(location_signals)} location groups")

    correlations = []
    for location_key, signals in location_signals.items():
        if len(signals) < 2:
            continue

        for seq_def in DEVELOPMENT_SEQUENCES:
            match = _check_sequence(signals, seq_def)
            if match:
                # Extract location info from signals
                sample = signals[0]
                match['location_key'] = location_key
                match['city'] = sample.get('city')
                match['state'] = sample.get('state')
                match['parcel_id'] = sample.get('parcel_id')
                match['entity_name'] = sample.get('entity_name')
                correlations.append(match)

    print(f"[SignalCorrelationEngine] Found {len(correlations)} sequence matches")

    if correlations:
        stored, boosted = _store_correlation_results(correlations)
        print(f"[SignalCorrelationEngine] Stored {stored} correlation signals, boosted {boosted} parcels")

        # Summary by sequence type
        seq_counts = defaultdict(int)
        for c in correlations:
            seq_counts[c['sequence_name']] += 1
        for seq_name, count in seq_counts.items():
            print(f"  {seq_name}: {count} matches")

        try:
            from app import log_intelligence_event
            log_intelligence_event(
                event_type='SIGNAL_CORRELATION',
                title=f"Signal sequence correlations detected",
                description=f"{len(correlations)} development signal sequences identified",
            )
        except Exception:
            pass

    print(f"[SignalCorrelationEngine] COMPLETE")
    return {'correlations_found': len(correlations)}
