"""
Developer Intent Detection Engine.
Analyzes early developer preparation signals and predicts future project launches
before land acquisition occurs.

Signal types detected:
- CONSULTANT_HIRING — civil engineering or planning consultant engagement
- ENGINEERING_ENGAGEMENT — structural/civil engineering firm engagement
- CONTRACTOR_PRECON — contractor preconstruction activity
- ENTITY_FORMATION — new LLC or entity formation by known developer
- MARKET_RESEARCH — feasibility studies or market research activity
- HIRING_EXPANSION — developer job postings in new geographic markets
"""
import uuid
from collections import defaultdict
from datetime import datetime, timedelta

from db import get_db


SIGNAL_TYPES = [
    'CONSULTANT_HIRING',
    'ENGINEERING_ENGAGEMENT',
    'CONTRACTOR_PRECON',
    'ENTITY_FORMATION',
    'MARKET_RESEARCH',
    'HIRING_EXPANSION',
]

# Weights for confidence scoring
SIGNAL_WEIGHTS = {
    'CONSULTANT_HIRING': 12,
    'ENGINEERING_ENGAGEMENT': 10,
    'CONTRACTOR_PRECON': 10,
    'ENTITY_FORMATION': 15,
    'MARKET_RESEARCH': 8,
    'HIRING_EXPANSION': 10,
}


def ingest_intent_signal(developer_id, signal_type, city, state,
                         related_entity=None, signal_strength=50):
    """Insert a single intent signal into developer_intent_signals."""
    conn = get_db()
    cur = conn.cursor()
    sid = str(uuid.uuid4())
    cur.execute(
        'INSERT INTO developer_intent_signals '
        '(id, developer_id, signal_type, city, state, related_entity, signal_strength) '
        'VALUES (?, ?, ?, ?, ?, ?, ?)',
        (sid, developer_id, signal_type, city, state, related_entity, signal_strength)
    )
    conn.commit()
    conn.close()
    return sid


def scan_contractor_precon_signals():
    """Detect contractor preconstruction signals from contractor_activity table."""
    conn = get_db()
    cur = conn.cursor()
    ingested = 0
    cutoff = (datetime.utcnow() - timedelta(days=90)).isoformat()

    try:
        cur.execute('''
            SELECT ca.contractor_id, ca.activity_type, ca.city, ca.state,
                   cf.firm_name, cdr.developer_id
            FROM contractor_activity ca
            LEFT JOIN contractor_firms cf ON ca.contractor_id = cf.id
            LEFT JOIN contractor_developer_relationships cdr ON ca.contractor_id = cdr.contractor_id
            WHERE ca.created_at >= ?
              AND ca.activity_type IN ('preconstruction', 'site_assessment', 'bid_submitted')
              AND cdr.developer_id IS NOT NULL
        ''', (cutoff,))
        rows = [dict(zip([d[0] for d in cur.description], r)) for r in cur.fetchall()]
    except Exception:
        rows = []

    for row in rows:
        # Check if signal already exists
        cur.execute(
            'SELECT id FROM developer_intent_signals '
            'WHERE developer_id = ? AND signal_type = ? AND city = ? AND state = ? '
            'AND related_entity = ?',
            (row['developer_id'], 'CONTRACTOR_PRECON', row['city'], row['state'],
             row.get('firm_name', ''))
        )
        if not cur.fetchone():
            ingest_intent_signal(
                developer_id=row['developer_id'],
                signal_type='CONTRACTOR_PRECON',
                city=row['city'],
                state=row['state'],
                related_entity=row.get('firm_name', ''),
                signal_strength=60,
            )
            ingested += 1

    conn.close()
    return ingested


def scan_engineering_signals():
    """Detect engineering engagement signals from contractor relationships."""
    conn = get_db()
    cur = conn.cursor()
    ingested = 0
    cutoff = (datetime.utcnow() - timedelta(days=90)).isoformat()

    try:
        cur.execute('''
            SELECT cdr.developer_id, cf.firm_name, cf.specialty, cf.city, cf.state
            FROM contractor_developer_relationships cdr
            JOIN contractor_firms cf ON cdr.contractor_id = cf.id
            WHERE cdr.created_at >= ?
              AND cf.specialty IN ('civil_engineering', 'structural_engineering',
                                   'geotechnical', 'environmental')
        ''', (cutoff,))
        rows = [dict(zip([d[0] for d in cur.description], r)) for r in cur.fetchall()]
    except Exception:
        rows = []

    for row in rows:
        cur.execute(
            'SELECT id FROM developer_intent_signals '
            'WHERE developer_id = ? AND signal_type = ? AND city = ? AND state = ? '
            'AND related_entity = ?',
            (row['developer_id'], 'ENGINEERING_ENGAGEMENT', row['city'], row['state'],
             row.get('firm_name', ''))
        )
        if not cur.fetchone():
            ingest_intent_signal(
                developer_id=row['developer_id'],
                signal_type='ENGINEERING_ENGAGEMENT',
                city=row['city'],
                state=row['state'],
                related_entity=row.get('firm_name', ''),
                signal_strength=55,
            )
            ingested += 1

    conn.close()
    return ingested


def scan_entity_formation_signals():
    """Detect new entity formations from developer_dna_profiles and project history."""
    conn = get_db()
    cur = conn.cursor()
    ingested = 0
    cutoff = (datetime.utcnow() - timedelta(days=90)).isoformat()

    try:
        cur.execute('''
            SELECT dph.developer_id, dph.city, dph.state, d.developer_name
            FROM developer_project_history dph
            JOIN developers d ON dph.developer_id = d.id
            WHERE dph.first_detected >= ?
              AND dph.project_stage = 'entity_formation'
        ''', (cutoff,))
        rows = [dict(zip([d[0] for d in cur.description], r)) for r in cur.fetchall()]
    except Exception:
        rows = []

    for row in rows:
        cur.execute(
            'SELECT id FROM developer_intent_signals '
            'WHERE developer_id = ? AND signal_type = ? AND city = ? AND state = ?',
            (row['developer_id'], 'ENTITY_FORMATION', row['city'], row['state'])
        )
        if not cur.fetchone():
            ingest_intent_signal(
                developer_id=row['developer_id'],
                signal_type='ENTITY_FORMATION',
                city=row['city'],
                state=row['state'],
                related_entity=row.get('developer_name', ''),
                signal_strength=70,
            )
            ingested += 1

    conn.close()
    return ingested


def scan_expansion_signals():
    """Detect hiring expansion and market research signals from expansion predictions."""
    conn = get_db()
    cur = conn.cursor()
    ingested = 0
    cutoff = (datetime.utcnow() - timedelta(days=90)).isoformat()

    try:
        cur.execute('''
            SELECT dep.developer_id, dep.predicted_city, dep.predicted_state,
                   dep.reasoning, d.developer_name
            FROM developer_expansion_predictions dep
            JOIN developers d ON dep.developer_id = d.id
            WHERE dep.created_at >= ?
              AND dep.confidence >= 60
        ''', (cutoff,))
        rows = [dict(zip([d[0] for d in cur.description], r)) for r in cur.fetchall()]
    except Exception:
        rows = []

    for row in rows:
        reasoning = (row.get('reasoning') or '').lower()

        # Hiring expansion signal
        if 'hiring' in reasoning or 'job posting' in reasoning or 'recruitment' in reasoning:
            cur.execute(
                'SELECT id FROM developer_intent_signals '
                'WHERE developer_id = ? AND signal_type = ? AND city = ? AND state = ?',
                (row['developer_id'], 'HIRING_EXPANSION',
                 row['predicted_city'], row['predicted_state'])
            )
            if not cur.fetchone():
                ingest_intent_signal(
                    developer_id=row['developer_id'],
                    signal_type='HIRING_EXPANSION',
                    city=row['predicted_city'],
                    state=row['predicted_state'],
                    related_entity=row.get('developer_name', ''),
                    signal_strength=50,
                )
                ingested += 1

        # Market research signal
        if 'feasibility' in reasoning or 'market research' in reasoning or 'market study' in reasoning:
            cur.execute(
                'SELECT id FROM developer_intent_signals '
                'WHERE developer_id = ? AND signal_type = ? AND city = ? AND state = ?',
                (row['developer_id'], 'MARKET_RESEARCH',
                 row['predicted_city'], row['predicted_state'])
            )
            if not cur.fetchone():
                ingest_intent_signal(
                    developer_id=row['developer_id'],
                    signal_type='MARKET_RESEARCH',
                    city=row['predicted_city'],
                    state=row['predicted_state'],
                    related_entity=row.get('developer_name', ''),
                    signal_strength=45,
                )
                ingested += 1

    conn.close()
    return ingested


def calculate_intent_confidence(signals):
    """
    Calculate confidence score for a set of intent signals.
    Formula: (signal_count * 15) + sum(type_weights) + (dna_match * 15)
    Capped at 100.
    """
    if not signals:
        return 0

    signal_count = len(signals)
    base_score = signal_count * 15

    # Add type-specific weights
    type_bonus = 0
    has_contractor = False
    has_engineering = False
    for s in signals:
        stype = s.get('signal_type', '')
        type_bonus += SIGNAL_WEIGHTS.get(stype, 5)
        if stype == 'CONTRACTOR_PRECON':
            has_contractor = True
        if stype == 'ENGINEERING_ENGAGEMENT':
            has_engineering = True

    # Contractor activity bonus
    contractor_bonus = 10 if has_contractor else 0
    # Engineering signals bonus
    engineering_bonus = 10 if has_engineering else 0

    total = base_score + type_bonus + contractor_bonus + engineering_bonus
    return min(total, 100)


def generate_reasoning(developer_name, city, state, signals):
    """Generate a human-readable explanation of the intent prediction."""
    signal_labels = {
        'CONSULTANT_HIRING': 'consultant hiring',
        'ENGINEERING_ENGAGEMENT': 'engineering engagement',
        'CONTRACTOR_PRECON': 'contractor consultation',
        'ENTITY_FORMATION': 'new LLC formation',
        'MARKET_RESEARCH': 'market feasibility research',
        'HIRING_EXPANSION': 'regional hiring expansion',
    }

    types = list({s.get('signal_type') for s in signals if s.get('signal_type')})
    labels = [signal_labels.get(t, t) for t in types]

    if len(labels) == 0:
        detail = 'preparation activity'
    elif len(labels) == 1:
        detail = labels[0]
    else:
        detail = ', '.join(labels[:-1]) + ' and ' + labels[-1]

    return (
        f"{developer_name} shows multiple pre-development signals in "
        f"{city} including {detail}."
    )


def analyze_intent_signals():
    """
    Core analysis: group signals by developer+city within 90-day window,
    create predictions for developers with 3+ signals in the same market.
    Returns list of new predictions created.
    """
    conn = get_db()
    cur = conn.cursor()
    cutoff = (datetime.utcnow() - timedelta(days=90)).isoformat()

    # Fetch recent signals
    cur.execute('''
        SELECT dis.id, dis.developer_id, dis.signal_type, dis.city, dis.state,
               dis.related_entity, dis.signal_strength, dis.created_at,
               d.developer_name
        FROM developer_intent_signals dis
        LEFT JOIN developers d ON dis.developer_id = d.id
        WHERE dis.created_at >= ?
        ORDER BY dis.developer_id, dis.city, dis.state
    ''', (cutoff,))
    cols = [d[0] for d in cur.description]
    all_signals = [dict(zip(cols, r)) for r in cur.fetchall()]

    # Group by developer + city + state
    groups = defaultdict(list)
    for sig in all_signals:
        key = (sig['developer_id'], sig['city'], sig['state'])
        groups[key].append(sig)

    new_predictions = []

    for (dev_id, city, state), signals in groups.items():
        if len(signals) < 3:
            continue

        developer_name = signals[0].get('developer_name') or 'Unknown Developer'
        confidence = calculate_intent_confidence(signals)
        reasoning = generate_reasoning(developer_name, city, state, signals)

        # Check if prediction already exists for this developer+market
        cur.execute(
            'SELECT id FROM developer_intent_predictions '
            'WHERE developer_id = ? AND predicted_city = ? AND predicted_state = ?',
            (dev_id, city, state)
        )
        existing = cur.fetchone()

        pid = str(uuid.uuid4())
        if existing:
            # Update existing prediction
            cur.execute(
                'UPDATE developer_intent_predictions '
                'SET signal_count = ?, confidence_score = ?, reasoning = ?, created_at = ? '
                'WHERE developer_id = ? AND predicted_city = ? AND predicted_state = ?',
                (len(signals), confidence, reasoning, datetime.utcnow().isoformat(),
                 dev_id, city, state)
            )
            pid = existing[0]
        else:
            # Create new prediction
            cur.execute(
                'INSERT INTO developer_intent_predictions '
                '(id, developer_id, predicted_city, predicted_state, '
                'signal_count, confidence_score, reasoning) '
                'VALUES (?, ?, ?, ?, ?, ?, ?)',
                (pid, dev_id, city, state, len(signals), confidence, reasoning)
            )

        new_predictions.append({
            'id': pid,
            'developer_id': dev_id,
            'developer_name': developer_name,
            'city': city,
            'state': state,
            'signal_count': len(signals),
            'confidence': confidence,
            'reasoning': reasoning,
            'is_update': bool(existing),
        })

        # Log intelligence feed event for new predictions
        if not existing:
            try:
                from app import log_intelligence_event
                log_intelligence_event(
                    event_type='DEVELOPER_INTENT',
                    title=f'Developer Intent Detected: {developer_name}',
                    description=reasoning,
                    city=city,
                    state=state,
                    related_entity=developer_name,
                    entity_id=pid,
                )
            except Exception as e:
                print(f"[IntentEngine] Feed event error: {e}")

    conn.commit()
    conn.close()
    return new_predictions
