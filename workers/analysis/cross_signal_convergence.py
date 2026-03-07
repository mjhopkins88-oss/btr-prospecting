"""
Cross Signal Convergence Engine.
Detects development opportunities by identifying multiple weak signals that
occur together within a geographic and temporal window.

Signal sources combined:
- permits
- zoning requests
- planning agendas
- engineering signals
- contractor intelligence
- entity filings
- land purchases
- infrastructure planning
- supply chain signals

Convergence rules:
- 2 signals within 90 days  → convergence score +20
- 3 signals within 120 days → convergence score +40
- 4 signals within 180 days → convergence score +70

Runs every 6 hours and updates existing clusters as new signals arrive.
"""
import uuid
from collections import defaultdict
from datetime import datetime, timedelta

from db import get_db


# ---------------------------------------------------------------------------
# Signal type definitions
# ---------------------------------------------------------------------------
SIGNAL_TYPES = [
    'PERMIT_FILING',
    'ZONING_REQUEST',
    'PLANNING_AGENDA',
    'ENGINEERING_ACTIVITY',
    'CONTRACTOR_SIGNAL',
    'ENTITY_FILING',
    'LAND_PURCHASE',
    'INFRASTRUCTURE_PLANNING',
    'SUPPLY_CHAIN_SIGNAL',
    'NEWS_SIGNAL',
]

# Importance weights per signal type (0.0–1.0)
SIGNAL_WEIGHTS = {
    'PERMIT_FILING': 0.9,
    'ZONING_REQUEST': 0.8,
    'ENGINEERING_ACTIVITY': 0.7,
    'CONTRACTOR_SIGNAL': 0.6,
    'ENTITY_FILING': 0.5,
    'LAND_PURCHASE': 0.9,
    'INFRASTRUCTURE_PLANNING': 0.7,
    'PLANNING_AGENDA': 0.6,
    'SUPPLY_CHAIN_SIGNAL': 0.4,
    'NEWS_SIGNAL': 0.3,
}

# Convergence rules: (min_signals, max_days, score_bonus)
CONVERGENCE_RULES = [
    (4, 180, 70),
    (3, 120, 40),
    (2, 90, 20),
]

# Threshold above which we emit an intelligence event
CONVERGENCE_EVENT_THRESHOLD = 40


# ---------------------------------------------------------------------------
# Table bootstrapping
# ---------------------------------------------------------------------------

def ensure_tables():
    """Create the convergence tables if they do not exist."""
    conn = get_db()
    cur = conn.cursor()

    cur.execute('''
        CREATE TABLE IF NOT EXISTS convergence_signals (
            id TEXT PRIMARY KEY,
            signal_type TEXT NOT NULL,
            entity TEXT,
            parcel_id TEXT,
            cluster_id TEXT,
            location TEXT,
            city TEXT,
            state TEXT,
            timestamp TEXT NOT NULL,
            confidence_score REAL DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS signal_convergence_events (
            id TEXT PRIMARY KEY,
            parcel_id TEXT,
            cluster_id TEXT,
            signals_detected INTEGER DEFAULT 0,
            convergence_score REAL DEFAULT 0,
            weighted_score REAL DEFAULT 0,
            probability_estimate REAL DEFAULT 0,
            first_signal_timestamp TEXT,
            last_signal_timestamp TEXT,
            signal_types TEXT,
            reasoning TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Signal ingestion
# ---------------------------------------------------------------------------

def ingest_signal(signal_type, entity=None, parcel_id=None, cluster_id=None,
                  location=None, city=None, state=None, timestamp=None,
                  confidence_score=50):
    """Insert a single convergence signal."""
    if signal_type not in SIGNAL_TYPES:
        print(f"[ConvergenceEngine] Unknown signal type: {signal_type}")
        return None

    conn = get_db()
    cur = conn.cursor()
    sid = str(uuid.uuid4())
    ts = timestamp or datetime.utcnow().isoformat()

    cur.execute(
        'INSERT INTO convergence_signals '
        '(id, signal_type, entity, parcel_id, cluster_id, location, '
        'city, state, timestamp, confidence_score) '
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        (sid, signal_type, entity, parcel_id, cluster_id, location,
         city, state, ts, confidence_score)
    )
    conn.commit()
    conn.close()
    return sid


# ---------------------------------------------------------------------------
# Signal scanning — harvest from existing platform tables
# ---------------------------------------------------------------------------

def scan_permit_signals():
    """Harvest permit filing signals from development_events."""
    conn = get_db()
    cur = conn.cursor()
    ingested = 0
    cutoff = (datetime.utcnow() - timedelta(days=180)).isoformat()

    try:
        cur.execute('''
            SELECT DISTINCT de.parcel_id, de.city, de.state, de.developer,
                   de.created_at
            FROM development_events de
            WHERE de.created_at >= ?
              AND de.event_type IN ('BUILDING_PERMIT', 'PERMIT_FILED',
                                    'PERMIT_APPROVED')
              AND de.parcel_id IS NOT NULL AND de.parcel_id != ''
        ''', (cutoff,))
        rows = [dict(zip([d[0] for d in cur.description], r))
                for r in cur.fetchall()]
    except Exception:
        rows = []

    for row in rows:
        cur.execute(
            'SELECT id FROM convergence_signals '
            'WHERE signal_type = ? AND parcel_id = ? AND entity = ?',
            ('PERMIT_FILING', row['parcel_id'], row.get('developer', ''))
        )
        if not cur.fetchone():
            ingest_signal(
                signal_type='PERMIT_FILING',
                entity=row.get('developer'),
                parcel_id=row['parcel_id'],
                city=row.get('city'),
                state=row.get('state'),
                timestamp=row.get('created_at'),
                confidence_score=85,
            )
            ingested += 1

    conn.close()
    return ingested


def scan_zoning_signals():
    """Harvest zoning request signals from development_events."""
    conn = get_db()
    cur = conn.cursor()
    ingested = 0
    cutoff = (datetime.utcnow() - timedelta(days=180)).isoformat()

    try:
        cur.execute('''
            SELECT DISTINCT de.parcel_id, de.city, de.state, de.developer,
                   de.created_at
            FROM development_events de
            WHERE de.created_at >= ?
              AND de.event_type IN ('ZONING_APPLICATION', 'ZONING_CHANGE',
                                    'REZONING')
              AND de.parcel_id IS NOT NULL AND de.parcel_id != ''
        ''', (cutoff,))
        rows = [dict(zip([d[0] for d in cur.description], r))
                for r in cur.fetchall()]
    except Exception:
        rows = []

    for row in rows:
        cur.execute(
            'SELECT id FROM convergence_signals '
            'WHERE signal_type = ? AND parcel_id = ? AND entity = ?',
            ('ZONING_REQUEST', row['parcel_id'], row.get('developer', ''))
        )
        if not cur.fetchone():
            ingest_signal(
                signal_type='ZONING_REQUEST',
                entity=row.get('developer'),
                parcel_id=row['parcel_id'],
                city=row.get('city'),
                state=row.get('state'),
                timestamp=row.get('created_at'),
                confidence_score=75,
            )
            ingested += 1

    conn.close()
    return ingested


def scan_engineering_signals():
    """Harvest engineering activity from contractor relationships."""
    conn = get_db()
    cur = conn.cursor()
    ingested = 0
    cutoff = (datetime.utcnow() - timedelta(days=180)).isoformat()

    try:
        cur.execute('''
            SELECT ca.contractor_id, ca.city, ca.state,
                   cf.firm_name, ca.created_at
            FROM contractor_activity ca
            LEFT JOIN contractor_firms cf ON ca.contractor_id = cf.id
            WHERE ca.created_at >= ?
              AND ca.activity_type IN ('engineering', 'site_assessment',
                                       'geotechnical', 'survey')
        ''', (cutoff,))
        rows = [dict(zip([d[0] for d in cur.description], r))
                for r in cur.fetchall()]
    except Exception:
        rows = []

    for row in rows:
        cur.execute(
            'SELECT id FROM convergence_signals '
            'WHERE signal_type = ? AND city = ? AND state = ? AND entity = ?',
            ('ENGINEERING_ACTIVITY', row.get('city', ''),
             row.get('state', ''), row.get('firm_name', ''))
        )
        if not cur.fetchone():
            ingest_signal(
                signal_type='ENGINEERING_ACTIVITY',
                entity=row.get('firm_name'),
                city=row.get('city'),
                state=row.get('state'),
                timestamp=row.get('created_at'),
                confidence_score=65,
            )
            ingested += 1

    conn.close()
    return ingested


def scan_contractor_signals():
    """Harvest contractor intelligence signals."""
    conn = get_db()
    cur = conn.cursor()
    ingested = 0
    cutoff = (datetime.utcnow() - timedelta(days=180)).isoformat()

    try:
        cur.execute('''
            SELECT ca.contractor_id, ca.city, ca.state,
                   cf.firm_name, ca.created_at
            FROM contractor_activity ca
            LEFT JOIN contractor_firms cf ON ca.contractor_id = cf.id
            WHERE ca.created_at >= ?
              AND ca.activity_type IN ('preconstruction', 'bid_submitted',
                                       'contract_awarded')
        ''', (cutoff,))
        rows = [dict(zip([d[0] for d in cur.description], r))
                for r in cur.fetchall()]
    except Exception:
        rows = []

    for row in rows:
        cur.execute(
            'SELECT id FROM convergence_signals '
            'WHERE signal_type = ? AND city = ? AND state = ? AND entity = ?',
            ('CONTRACTOR_SIGNAL', row.get('city', ''),
             row.get('state', ''), row.get('firm_name', ''))
        )
        if not cur.fetchone():
            ingest_signal(
                signal_type='CONTRACTOR_SIGNAL',
                entity=row.get('firm_name'),
                city=row.get('city'),
                state=row.get('state'),
                timestamp=row.get('created_at'),
                confidence_score=60,
            )
            ingested += 1

    conn.close()
    return ingested


def scan_entity_filing_signals():
    """Harvest entity filing signals from developer project history."""
    conn = get_db()
    cur = conn.cursor()
    ingested = 0
    cutoff = (datetime.utcnow() - timedelta(days=180)).isoformat()

    try:
        cur.execute('''
            SELECT dph.developer_id, dph.city, dph.state, d.developer_name,
                   dph.first_detected
            FROM developer_project_history dph
            JOIN developers d ON dph.developer_id = d.id
            WHERE dph.first_detected >= ?
              AND dph.project_stage = 'entity_formation'
        ''', (cutoff,))
        rows = [dict(zip([d[0] for d in cur.description], r))
                for r in cur.fetchall()]
    except Exception:
        rows = []

    for row in rows:
        cur.execute(
            'SELECT id FROM convergence_signals '
            'WHERE signal_type = ? AND city = ? AND state = ? AND entity = ?',
            ('ENTITY_FILING', row.get('city', ''),
             row.get('state', ''), row.get('developer_name', ''))
        )
        if not cur.fetchone():
            ingest_signal(
                signal_type='ENTITY_FILING',
                entity=row.get('developer_name'),
                city=row.get('city'),
                state=row.get('state'),
                timestamp=row.get('first_detected'),
                confidence_score=55,
            )
            ingested += 1

    conn.close()
    return ingested


def scan_land_purchase_signals():
    """Harvest land purchase signals from property_signals and development_events."""
    conn = get_db()
    cur = conn.cursor()
    ingested = 0
    cutoff = (datetime.utcnow() - timedelta(days=180)).isoformat()

    try:
        cur.execute('''
            SELECT DISTINCT ps.parcel_id, ps.entity_name, ps.city, ps.state,
                   ps.created_at
            FROM property_signals ps
            WHERE ps.created_at >= ?
              AND ps.signal_type = 'LAND_PURCHASE'
              AND ps.parcel_id IS NOT NULL AND ps.parcel_id != ''
        ''', (cutoff,))
        rows = [dict(zip([d[0] for d in cur.description], r))
                for r in cur.fetchall()]
    except Exception:
        rows = []

    for row in rows:
        cur.execute(
            'SELECT id FROM convergence_signals '
            'WHERE signal_type = ? AND parcel_id = ? AND entity = ?',
            ('LAND_PURCHASE', row.get('parcel_id', ''),
             row.get('entity_name', ''))
        )
        if not cur.fetchone():
            ingest_signal(
                signal_type='LAND_PURCHASE',
                entity=row.get('entity_name'),
                parcel_id=row.get('parcel_id'),
                city=row.get('city'),
                state=row.get('state'),
                timestamp=row.get('created_at'),
                confidence_score=80,
            )
            ingested += 1

    conn.close()
    return ingested


def scan_infrastructure_signals():
    """Harvest infrastructure planning signals from development_events."""
    conn = get_db()
    cur = conn.cursor()
    ingested = 0
    cutoff = (datetime.utcnow() - timedelta(days=180)).isoformat()

    try:
        cur.execute('''
            SELECT DISTINCT de.parcel_id, de.city, de.state, de.developer,
                   de.created_at
            FROM development_events de
            WHERE de.created_at >= ?
              AND de.event_type IN ('UTILITY_PLAN', 'UTILITY_EXTENSION',
                                    'INFRASTRUCTURE', 'ROAD_IMPROVEMENT')
        ''', (cutoff,))
        rows = [dict(zip([d[0] for d in cur.description], r))
                for r in cur.fetchall()]
    except Exception:
        rows = []

    for row in rows:
        loc_key = row.get('parcel_id') or f"{row.get('city', '')}_{row.get('state', '')}"
        cur.execute(
            'SELECT id FROM convergence_signals '
            'WHERE signal_type = ? AND city = ? AND state = ? '
            'AND (parcel_id = ? OR parcel_id IS NULL)',
            ('INFRASTRUCTURE_PLANNING', row.get('city', ''),
             row.get('state', ''), row.get('parcel_id', ''))
        )
        if not cur.fetchone():
            ingest_signal(
                signal_type='INFRASTRUCTURE_PLANNING',
                entity=row.get('developer'),
                parcel_id=row.get('parcel_id'),
                city=row.get('city'),
                state=row.get('state'),
                timestamp=row.get('created_at'),
                confidence_score=65,
            )
            ingested += 1

    conn.close()
    return ingested


def scan_all_signals():
    """Run all signal scanners and return summary counts."""
    scanners = [
        ('permit', scan_permit_signals),
        ('zoning', scan_zoning_signals),
        ('engineering', scan_engineering_signals),
        ('contractor', scan_contractor_signals),
        ('entity_filing', scan_entity_filing_signals),
        ('land_purchase', scan_land_purchase_signals),
        ('infrastructure', scan_infrastructure_signals),
    ]
    results = {}
    for name, func in scanners:
        try:
            results[name] = func()
        except Exception as e:
            print(f"[ConvergenceEngine] Scanner {name} error: {e}")
            results[name] = 0
    return results


# ---------------------------------------------------------------------------
# Convergence scoring
# ---------------------------------------------------------------------------

def _parse_timestamp(ts):
    """Parse ISO timestamp string to datetime, return None on failure."""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace('Z', '+00:00').replace('+00:00', ''))
    except (ValueError, AttributeError):
        return None


def calculate_convergence_score(signals):
    """
    Apply convergence rules to a group of signals.
    Returns (convergence_score, weighted_score, probability_estimate).
    """
    if not signals:
        return 0, 0.0, 0.0

    timestamps = []
    for s in signals:
        ts = _parse_timestamp(s.get('timestamp'))
        if ts:
            timestamps.append(ts)

    if not timestamps:
        return 0, 0.0, 0.0

    timestamps.sort()
    first_ts = timestamps[0]
    last_ts = timestamps[-1]
    span_days = (last_ts - first_ts).days

    signal_count = len(signals)

    # Apply convergence rules (highest matching rule wins)
    convergence_score = 0
    for min_signals, max_days, bonus in CONVERGENCE_RULES:
        if signal_count >= min_signals and span_days <= max_days:
            convergence_score = bonus
            break

    # Calculate weighted score from signal importance
    weighted_score = 0.0
    for s in signals:
        stype = s.get('signal_type', '')
        weight = SIGNAL_WEIGHTS.get(stype, 0.3)
        confidence = (s.get('confidence_score') or 50) / 100.0
        weighted_score += weight * confidence

    # Probability estimate: combine convergence and weighted scores
    # Normalize weighted_score to 0-100 range (max ~9 signals * 1.0 * 1.0 = 9.0)
    normalized_weighted = min(weighted_score / 5.0 * 100, 100)
    probability_estimate = min(
        (convergence_score * 0.6 + normalized_weighted * 0.4),
        100
    )

    return convergence_score, round(weighted_score, 3), round(probability_estimate, 1)


def generate_convergence_reasoning(signals, convergence_score, probability_estimate):
    """Generate a human-readable explanation of the convergence event."""
    type_labels = {
        'PERMIT_FILING': 'permit filing',
        'ZONING_REQUEST': 'zoning request',
        'PLANNING_AGENDA': 'planning agenda item',
        'ENGINEERING_ACTIVITY': 'engineering activity',
        'CONTRACTOR_SIGNAL': 'contractor intelligence',
        'ENTITY_FILING': 'entity filing',
        'LAND_PURCHASE': 'land purchase',
        'INFRASTRUCTURE_PLANNING': 'infrastructure planning',
        'SUPPLY_CHAIN_SIGNAL': 'supply chain activity',
        'NEWS_SIGNAL': 'news signal',
    }

    types = list({s.get('signal_type') for s in signals if s.get('signal_type')})
    labels = [type_labels.get(t, t) for t in types]

    if len(labels) == 0:
        detail = 'multiple development signals'
    elif len(labels) == 1:
        detail = labels[0]
    else:
        detail = ', '.join(labels[:-1]) + ' and ' + labels[-1]

    return (
        f"Cross-signal convergence detected ({len(signals)} signals): {detail}. "
        f"Convergence score {convergence_score}, "
        f"estimated probability {probability_estimate}%."
    )


# ---------------------------------------------------------------------------
# Core analysis — cluster signals and detect convergence
# ---------------------------------------------------------------------------

def analyze_convergence():
    """
    Core analysis: group signals by parcel_id (or city+state cluster),
    apply convergence rules, and create/update signal_convergence_events.
    Returns list of convergence events created or updated.
    """
    conn = get_db()
    cur = conn.cursor()

    # Fetch all signals from the last 180 days
    cutoff = (datetime.utcnow() - timedelta(days=180)).isoformat()
    cur.execute('''
        SELECT id, signal_type, entity, parcel_id, cluster_id,
               location, city, state, timestamp, confidence_score
        FROM convergence_signals
        WHERE timestamp >= ?
        ORDER BY parcel_id, city, state, timestamp
    ''', (cutoff,))
    cols = [d[0] for d in cur.description]
    all_signals = [dict(zip(cols, r)) for r in cur.fetchall()]

    # Group by parcel_id first, then by city+state for non-parcel signals
    parcel_groups = defaultdict(list)
    cluster_groups = defaultdict(list)

    for sig in all_signals:
        pid = sig.get('parcel_id')
        if pid and pid.strip():
            parcel_groups[pid].append(sig)
        else:
            city = sig.get('city', '')
            state = sig.get('state', '')
            if city and state:
                cluster_key = f"{city}_{state}"
                cluster_groups[cluster_key].append(sig)

    events = []

    # Process parcel-level convergence
    for parcel_id, signals in parcel_groups.items():
        if len(signals) < 2:
            continue

        convergence_score, weighted_score, probability_estimate = \
            calculate_convergence_score(signals)

        if convergence_score == 0:
            continue

        event = _upsert_convergence_event(
            cur, parcel_id=parcel_id, cluster_id=None,
            signals=signals, convergence_score=convergence_score,
            weighted_score=weighted_score,
            probability_estimate=probability_estimate,
        )
        if event:
            events.append(event)

    # Process cluster-level convergence (city+state)
    for cluster_key, signals in cluster_groups.items():
        if len(signals) < 2:
            continue

        convergence_score, weighted_score, probability_estimate = \
            calculate_convergence_score(signals)

        if convergence_score == 0:
            continue

        event = _upsert_convergence_event(
            cur, parcel_id=None, cluster_id=cluster_key,
            signals=signals, convergence_score=convergence_score,
            weighted_score=weighted_score,
            probability_estimate=probability_estimate,
        )
        if event:
            events.append(event)

    conn.commit()
    conn.close()
    return events


def _upsert_convergence_event(cur, parcel_id, cluster_id, signals,
                              convergence_score, weighted_score,
                              probability_estimate):
    """Create or update a signal_convergence_events row."""
    timestamps = []
    for s in signals:
        ts = _parse_timestamp(s.get('timestamp'))
        if ts:
            timestamps.append(ts)
    timestamps.sort()

    first_ts = timestamps[0].isoformat() if timestamps else None
    last_ts = timestamps[-1].isoformat() if timestamps else None
    signal_types = ','.join(sorted({s.get('signal_type', '') for s in signals}))
    reasoning = generate_convergence_reasoning(
        signals, convergence_score, probability_estimate)
    now = datetime.utcnow().isoformat()

    # Check for existing event
    if parcel_id:
        cur.execute(
            'SELECT id, convergence_score FROM signal_convergence_events '
            'WHERE parcel_id = ?',
            (parcel_id,)
        )
    else:
        cur.execute(
            'SELECT id, convergence_score FROM signal_convergence_events '
            'WHERE cluster_id = ?',
            (cluster_id,)
        )
    existing = cur.fetchone()

    if existing:
        eid = existing[0]
        cur.execute('''
            UPDATE signal_convergence_events
            SET signals_detected = ?, convergence_score = ?,
                weighted_score = ?, probability_estimate = ?,
                first_signal_timestamp = ?, last_signal_timestamp = ?,
                signal_types = ?, reasoning = ?, updated_at = ?
            WHERE id = ?
        ''', (len(signals), convergence_score, weighted_score,
              probability_estimate, first_ts, last_ts,
              signal_types, reasoning, now, eid))
        is_update = True
    else:
        eid = str(uuid.uuid4())
        cur.execute('''
            INSERT INTO signal_convergence_events
            (id, parcel_id, cluster_id, signals_detected, convergence_score,
             weighted_score, probability_estimate, first_signal_timestamp,
             last_signal_timestamp, signal_types, reasoning,
             created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (eid, parcel_id, cluster_id, len(signals), convergence_score,
              weighted_score, probability_estimate, first_ts, last_ts,
              signal_types, reasoning, now, now))
        is_update = False

    event = {
        'id': eid,
        'parcel_id': parcel_id,
        'cluster_id': cluster_id,
        'signals_detected': len(signals),
        'convergence_score': convergence_score,
        'weighted_score': weighted_score,
        'probability_estimate': probability_estimate,
        'first_signal_timestamp': first_ts,
        'last_signal_timestamp': last_ts,
        'is_update': is_update,
    }

    # Emit intelligence event if score exceeds threshold
    if convergence_score >= CONVERGENCE_EVENT_THRESHOLD and not is_update:
        _emit_intelligence_event(event, signals)

    # Boost parcel development probability if parcel-level convergence
    if parcel_id and convergence_score >= CONVERGENCE_EVENT_THRESHOLD:
        _boost_parcel_probability(cur, parcel_id, probability_estimate)

    return event


def _boost_parcel_probability(cur, parcel_id, probability_estimate):
    """Increase development_probability score for the parcel based on convergence."""
    boost = round(probability_estimate * 0.15, 1)  # 15% of convergence probability
    try:
        cur.execute(
            'SELECT id, probability_score FROM parcel_development_probability '
            'WHERE parcel_id = ?',
            (parcel_id,)
        )
        existing = cur.fetchone()
        if existing:
            new_score = min(existing[1] + boost, 100)
            cur.execute(
                'UPDATE parcel_development_probability '
                'SET probability_score = ?, '
                'reasoning = reasoning || ? '
                'WHERE parcel_id = ?',
                (new_score,
                 f' Cross-signal convergence boost +{boost}.',
                 parcel_id)
            )
    except Exception as e:
        print(f"[ConvergenceEngine] Parcel probability boost error: {e}")


def _emit_intelligence_event(event, signals):
    """Log a DEVELOPMENT_SIGNAL_CONVERGENCE event to the intelligence feed."""
    try:
        from app import log_intelligence_event

        location = event.get('parcel_id') or event.get('cluster_id') or 'Unknown'
        # Extract city from signals if available
        city = None
        state = None
        for s in signals:
            if s.get('city'):
                city = s['city']
                state = s.get('state')
                break

        log_intelligence_event(
            event_type='DEVELOPMENT_SIGNAL_CONVERGENCE',
            title=f"Signal Convergence Detected — {location}",
            description=(
                f"{event['signals_detected']} signals converging "
                f"(score {event['convergence_score']}, "
                f"probability {event['probability_estimate']}%)"
            ),
            city=city,
            state=state,
            related_entity=location,
            entity_id=event['id'],
        )
    except Exception as e:
        print(f"[ConvergenceEngine] Intelligence event error: {e}")


# ---------------------------------------------------------------------------
# Pipeline entry point (runs every 6 hours)
# ---------------------------------------------------------------------------

def run_convergence_engine():
    """
    Main entry point for the Cross Signal Convergence Engine.
    Designed to run every 6 hours via scheduler.
    """
    print(f"\n{'='*60}")
    print(f"[ConvergenceEngine] START — {datetime.utcnow().isoformat()}")
    print(f"{'='*60}")

    # Step 1: Ensure tables exist
    try:
        ensure_tables()
        print("[ConvergenceEngine] Tables verified")
    except Exception as e:
        print(f"[ConvergenceEngine] Table setup error: {e}")

    # Step 2: Scan and ingest signals from all sources
    try:
        scan_results = scan_all_signals()
        total_ingested = sum(scan_results.values())
        print(f"[ConvergenceEngine] Signals ingested: {total_ingested} "
              f"(breakdown: {scan_results})")
    except Exception as e:
        print(f"[ConvergenceEngine] Signal scan error: {e}")
        scan_results = {}

    # Step 3: Analyze convergence
    try:
        events = analyze_convergence()
        new_events = [e for e in events if not e.get('is_update')]
        updated_events = [e for e in events if e.get('is_update')]
        print(f"[ConvergenceEngine] Convergence events: "
              f"{len(new_events)} new, {len(updated_events)} updated")
    except Exception as e:
        print(f"[ConvergenceEngine] Analysis error: {e}")
        events = []

    print(f"[ConvergenceEngine] COMPLETE — {datetime.utcnow().isoformat()}")
    print(f"{'='*60}\n")

    return {
        'signals_ingested': scan_results,
        'convergence_events_new': len([e for e in events if not e.get('is_update')]),
        'convergence_events_updated': len([e for e in events if e.get('is_update')]),
        'total_events': len(events),
    }
