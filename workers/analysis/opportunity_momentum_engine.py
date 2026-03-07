"""
Opportunity Momentum Engine.
Tracks how development signals accumulate over time for each parcel
or development cluster. Calculates a momentum_score that increases
when signals occur in sequence within short time windows.

Scoring model:
  2 signals within 90 days  → +20
  3 signals within 120 days → +40
  4 signals within 180 days → +60
  5+ signals within 180 days → +80

Momentum score is used to boost development_probability.
"""
import uuid
from collections import defaultdict
from datetime import datetime, timedelta

from db import get_db


# ---------------------------------------------------------------------------
# Signal types that contribute to momentum
# ---------------------------------------------------------------------------
MOMENTUM_SIGNAL_TYPES = {
    # Land transactions
    'LAND_PURCHASE', 'DEED_TRANSFER', 'OWNER_CHANGE',
    # Plat filings
    'SUBDIVISION_PLAT', 'PRELIMINARY_PLAT', 'FINAL_PLAT', 'LOT_SPLIT',
    # Zoning / planning
    'ZONING_AGENDA_ITEM', 'SITE_PLAN_SUBMISSION', 'SUBDIVISION_APPLICATION',
    'REZONING_REQUEST', 'DEVELOPMENT_REVIEW_CASE',
    # Permits
    'BUILDING_PERMIT', 'MULTIFAMILY_PERMIT', 'SUBDIVISION_PERMIT',
    'SITE_DEVELOPMENT_PERMIT', 'RESIDENTIAL_COMPLEX_PERMIT',
    # Contractor / supply chain
    'CONTRACTOR_BID', 'SITE_PLAN_PREP', 'ENGINEERING_PLAN_SUBMISSION',
    'CIVIL_ENGINEERING_PLAN', 'SITE_PREP_ACTIVITY',
    'UTILITY_CONNECTION_REQUEST', 'INFRASTRUCTURE_BID',
    # Financing
    'CONSTRUCTION_FINANCING', 'COMMERCIAL_MORTGAGE', 'SECURED_LOAN',
    # Developer expansion
    'DEVELOPER_EXPANSION',
}

# Momentum scoring thresholds
MOMENTUM_THRESHOLDS = [
    # (min_signals, max_days, score_boost)
    (5, 180, 80),
    (4, 180, 60),
    (3, 120, 40),
    (2, 90, 20),
]


# ---------------------------------------------------------------------------
# Collect signal sequences per parcel
# ---------------------------------------------------------------------------

def _collect_parcel_signals():
    """
    Gather signals per parcel, sorted by date.
    Returns dict: parcel_id → list of (signal_type, created_at) tuples.
    """
    conn = get_db()
    cur = conn.cursor()

    cur.execute('''
        SELECT parcel_id, signal_type, created_at
        FROM property_signals
        WHERE parcel_id IS NOT NULL AND parcel_id != ''
        ORDER BY parcel_id, created_at ASC
    ''')
    rows = cur.fetchall()
    conn.close()

    parcel_signals = defaultdict(list)
    for parcel_id, signal_type, created_at in rows:
        if signal_type in MOMENTUM_SIGNAL_TYPES:
            parcel_signals[parcel_id].append((signal_type, created_at))

    return parcel_signals


def _collect_cluster_signals():
    """
    Gather signals per city-entity cluster (for parcels without IDs).
    Returns dict: (city, state, entity) → list of (signal_type, created_at).
    """
    conn = get_db()
    cur = conn.cursor()

    cur.execute('''
        SELECT city, state, entity_name, signal_type, created_at
        FROM property_signals
        WHERE (parcel_id IS NULL OR parcel_id = '')
        AND city IS NOT NULL AND city != ''
        AND entity_name IS NOT NULL AND entity_name != ''
        ORDER BY city, state, entity_name, created_at ASC
    ''')
    rows = cur.fetchall()
    conn.close()

    cluster_signals = defaultdict(list)
    for city, state, entity, signal_type, created_at in rows:
        if signal_type in MOMENTUM_SIGNAL_TYPES:
            cluster_signals[(city, state, entity)].append((signal_type, created_at))

    return cluster_signals


# ---------------------------------------------------------------------------
# Momentum calculation
# ---------------------------------------------------------------------------

def _parse_timestamp(ts):
    """Parse a timestamp string to datetime."""
    if isinstance(ts, datetime):
        return ts
    try:
        return datetime.fromisoformat(str(ts).replace('Z', '+00:00')).replace(tzinfo=None)
    except (ValueError, TypeError):
        return None


def _calculate_momentum(signals):
    """
    Calculate momentum score for a list of (signal_type, created_at) tuples.
    Returns (momentum_score, signal_sequence_length, signal_sequence_start).
    """
    if len(signals) < 2:
        return 0, len(signals), None

    # Parse timestamps
    dated_signals = []
    for sig_type, created_at in signals:
        dt = _parse_timestamp(created_at)
        if dt:
            dated_signals.append((sig_type, dt))

    if len(dated_signals) < 2:
        return 0, len(dated_signals), None

    # Sort by date
    dated_signals.sort(key=lambda x: x[1])

    first_date = dated_signals[0][1]
    last_date = dated_signals[-1][1]
    span_days = (last_date - first_date).days

    signal_count = len(dated_signals)
    momentum = 0

    # Apply scoring thresholds — take the highest matching
    for min_signals, max_days, score_boost in MOMENTUM_THRESHOLDS:
        if signal_count >= min_signals and span_days <= max_days:
            momentum = score_boost
            break

    # Acceleration bonus: if signals are accelerating (recent signals closer together)
    if signal_count >= 3:
        mid = signal_count // 2
        first_half_span = (dated_signals[mid][1] - dated_signals[0][1]).days or 1
        second_half_span = (dated_signals[-1][1] - dated_signals[mid][1]).days or 1
        if second_half_span < first_half_span:
            # Signals are accelerating — add bonus
            momentum = min(100, momentum + 10)

    # Diversity bonus: more unique signal types = stronger momentum
    unique_types = len(set(s[0] for s in dated_signals))
    if unique_types >= 4:
        momentum = min(100, momentum + 10)
    elif unique_types >= 3:
        momentum = min(100, momentum + 5)

    return momentum, signal_count, first_date.isoformat()


# ---------------------------------------------------------------------------
# Store momentum scores
# ---------------------------------------------------------------------------

def _store_parcel_momentum(parcel_id, momentum_score, seq_length, seq_start):
    """Store momentum data for a parcel."""
    conn = get_db()
    cur = conn.cursor()

    # Update parcel with momentum data
    cur.execute('''
        UPDATE parcels
        SET development_momentum_score = ?,
            signal_sequence_length = ?,
            signal_sequence_start = ?
        WHERE parcel_id = ?
    ''', (momentum_score, seq_length, seq_start, parcel_id))

    # Boost development_probability based on momentum
    if momentum_score >= 40:
        boost = min(20, momentum_score // 5)
        cur.execute('''
            UPDATE parcels
            SET development_probability = MIN(99,
                COALESCE(development_probability, 0) + ?)
            WHERE parcel_id = ?
        ''', (boost, parcel_id))

    conn.commit()
    conn.close()


def _store_cluster_momentum(city, state, entity, momentum_score, seq_length, seq_start):
    """Store momentum data as a property signal for entity-city clusters."""
    if momentum_score < 20:
        return

    conn = get_db()
    cur = conn.cursor()

    # Check if momentum signal already exists
    cur.execute('''
        SELECT id FROM property_signals
        WHERE signal_type = 'MOMENTUM_SIGNAL'
        AND city = ? AND state = ? AND entity_name = ?
    ''', (city, state, entity))

    existing = cur.fetchone()
    metadata = json.dumps({
        'momentum_score': momentum_score,
        'signal_sequence_length': seq_length,
        'signal_sequence_start': seq_start,
    })

    if existing:
        cur.execute('''
            UPDATE property_signals
            SET metadata = ?, created_at = ?
            WHERE id = ?
        ''', (metadata, datetime.utcnow().isoformat(), existing[0]))
    else:
        cur.execute('''
            INSERT INTO property_signals
                (id, signal_type, city, state, entity_name, metadata, created_at)
            VALUES (?, 'MOMENTUM_SIGNAL', ?, ?, ?, ?, ?)
        ''', (str(uuid.uuid4()), city, state, entity, metadata,
              datetime.utcnow().isoformat()))

    conn.commit()
    conn.close()


# Need json for metadata serialization
import json


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_opportunity_momentum_engine():
    """
    Main entry point — calculate momentum scores for all parcels
    and development clusters.
    """
    print("[MomentumEngine] Starting opportunity momentum analysis...")

    # Step 1: Process parcel-level momentum
    parcel_signals = _collect_parcel_signals()
    print(f"[MomentumEngine] Analyzing momentum for {len(parcel_signals)} parcels")

    parcel_count = 0
    high_momentum = 0
    for parcel_id, signals in parcel_signals.items():
        momentum, seq_len, seq_start = _calculate_momentum(signals)
        if momentum > 0:
            _store_parcel_momentum(parcel_id, momentum, seq_len, seq_start)
            parcel_count += 1
            if momentum >= 60:
                high_momentum += 1

    print(f"[MomentumEngine] Updated {parcel_count} parcels ({high_momentum} high-momentum)")

    # Step 2: Process cluster-level momentum
    cluster_signals = _collect_cluster_signals()
    print(f"[MomentumEngine] Analyzing momentum for {len(cluster_signals)} clusters")

    cluster_count = 0
    for (city, state, entity), signals in cluster_signals.items():
        momentum, seq_len, seq_start = _calculate_momentum(signals)
        if momentum >= 20:
            _store_cluster_momentum(city, state, entity, momentum, seq_len, seq_start)
            cluster_count += 1

    print(f"[MomentumEngine] Created {cluster_count} cluster momentum signals")

    result = {
        'parcels_analyzed': len(parcel_signals),
        'parcels_with_momentum': parcel_count,
        'high_momentum_parcels': high_momentum,
        'clusters_analyzed': len(cluster_signals),
        'clusters_with_momentum': cluster_count,
    }
    print(f"[MomentumEngine] Complete: {result}")
    return result


if __name__ == '__main__':
    run_opportunity_momentum_engine()
