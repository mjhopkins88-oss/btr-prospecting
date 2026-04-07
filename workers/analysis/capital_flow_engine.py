"""
Capital Flow Detection Engine.
Analyzes capital signals and detects financing activity linked to development.

Detects financing events that indicate a project is about to move forward:
- CONSTRUCTION_LOAN — construction loan filings
- LAND_ACQUISITION_LOAN — land acquisition financing
- DEBT_PLACEMENT — debt placement announcements
- EQUITY_INVESTMENT — equity investment announcements
- JOINT_VENTURE — joint venture announcements
- FUND_DEPLOYMENT — fund deployment / private credit activity

Signal sources:
- LOAN_RECORD — county loan records
- PRESS_RELEASE — press releases and news
- SEC_FILING — SEC filings
- LENDER_ACTIVITY — lender announcements
- PRIVATE_CREDIT_FUNDING — private credit activity
"""
import uuid
from collections import defaultdict
from datetime import datetime, timedelta

from db import get_db


CAPITAL_EVENT_TYPES = [
    'CONSTRUCTION_LOAN',
    'LAND_ACQUISITION_LOAN',
    'DEBT_PLACEMENT',
    'EQUITY_INVESTMENT',
    'JOINT_VENTURE',
    'FUND_DEPLOYMENT',
]

SIGNAL_TYPES = [
    'LOAN_RECORD',
    'PRESS_RELEASE',
    'SEC_FILING',
    'LENDER_ACTIVITY',
    'PRIVATE_CREDIT_FUNDING',
]

# Weights for confidence scoring
EVENT_WEIGHTS = {
    'CONSTRUCTION_LOAN': 25,
    'LAND_ACQUISITION_LOAN': 20,
    'DEBT_PLACEMENT': 15,
    'EQUITY_INVESTMENT': 20,
    'JOINT_VENTURE': 15,
    'FUND_DEPLOYMENT': 15,
}


def ingest_capital_signal(developer_id, signal_type, city, state, signal_strength=50):
    """Insert a single capital signal into capital_signals."""
    conn = get_db()
    cur = conn.cursor()
    sid = str(uuid.uuid4())
    cur.execute(
        'INSERT INTO capital_signals '
        '(id, developer_id, signal_type, city, state, signal_strength) '
        'VALUES (?, ?, ?, ?, ?, ?)',
        (sid, developer_id, signal_type, city, state, signal_strength)
    )
    conn.commit()
    conn.close()
    return sid


def ingest_capital_event(developer_id, company_name, event_type, city, state,
                         loan_amount=None, lender_name=None, related_project=None,
                         source=None):
    """Insert a capital event into capital_events."""
    conn = get_db()
    cur = conn.cursor()
    eid = str(uuid.uuid4())
    cur.execute(
        'INSERT INTO capital_events '
        '(id, developer_id, company_name, event_type, city, state, '
        'loan_amount, lender_name, related_project, source) '
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        (eid, developer_id, company_name, event_type, city, state,
         loan_amount, lender_name, related_project, source)
    )
    conn.commit()
    conn.close()
    return eid


def scan_loan_signals():
    """Detect construction/acquisition loan signals from capital_events."""
    conn = get_db()
    cur = conn.cursor()
    ingested = 0
    cutoff = (datetime.utcnow() - timedelta(days=90)).isoformat()

    try:
        cur.execute('''
            SELECT id, developer_id, event_type, city, state, company_name
            FROM capital_events
            WHERE created_at >= ?
              AND event_type IN ('CONSTRUCTION_LOAN', 'LAND_ACQUISITION_LOAN')
        ''', (cutoff,))
        rows = [dict(zip([d[0] for d in cur.description], r)) for r in cur.fetchall()]
    except Exception:
        rows = []

    for row in rows:
        cur.execute(
            'SELECT id FROM capital_signals '
            'WHERE developer_id = ? AND signal_type = ? AND city = ? AND state = ?',
            (row['developer_id'], 'LOAN_RECORD', row['city'], row['state'])
        )
        if not cur.fetchone():
            sid = str(uuid.uuid4())
            cur.execute(
                'INSERT INTO capital_signals '
                '(id, developer_id, signal_type, city, state, signal_strength) '
                'VALUES (?, ?, ?, ?, ?, ?)',
                (sid, row['developer_id'], 'LOAN_RECORD', row['city'], row['state'], 75)
            )
            ingested += 1

    conn.commit()
    conn.close()
    return ingested


def scan_equity_signals():
    """Detect equity and JV signals from capital_events."""
    conn = get_db()
    cur = conn.cursor()
    ingested = 0
    cutoff = (datetime.utcnow() - timedelta(days=90)).isoformat()

    try:
        cur.execute('''
            SELECT id, developer_id, event_type, city, state, company_name
            FROM capital_events
            WHERE created_at >= ?
              AND event_type IN ('EQUITY_INVESTMENT', 'JOINT_VENTURE', 'FUND_DEPLOYMENT')
        ''', (cutoff,))
        rows = [dict(zip([d[0] for d in cur.description], r)) for r in cur.fetchall()]
    except Exception:
        rows = []

    for row in rows:
        stype = 'PRIVATE_CREDIT_FUNDING' if row['event_type'] == 'FUND_DEPLOYMENT' else 'PRESS_RELEASE'
        cur.execute(
            'SELECT id FROM capital_signals '
            'WHERE developer_id = ? AND signal_type = ? AND city = ? AND state = ?',
            (row['developer_id'], stype, row['city'], row['state'])
        )
        if not cur.fetchone():
            sid = str(uuid.uuid4())
            cur.execute(
                'INSERT INTO capital_signals '
                '(id, developer_id, signal_type, city, state, signal_strength) '
                'VALUES (?, ?, ?, ?, ?, ?)',
                (sid, row['developer_id'], stype, row['city'], row['state'], 65)
            )
            ingested += 1

    conn.commit()
    conn.close()
    return ingested


def scan_contractor_capital_signals():
    """Cross-reference contractor activity with capital events for corroboration."""
    conn = get_db()
    cur = conn.cursor()
    ingested = 0
    cutoff = (datetime.utcnow() - timedelta(days=90)).isoformat()

    try:
        cur.execute('''
            SELECT DISTINCT cdr.developer_id, ca.city, ca.state
            FROM contractor_activity ca
            JOIN contractor_developer_relationships cdr ON ca.contractor_id = cdr.contractor_id
            WHERE ca.created_at >= ?
              AND ca.activity_type IN ('preconstruction', 'bid_submitted')
              AND cdr.developer_id IN (
                  SELECT DISTINCT developer_id FROM capital_events WHERE created_at >= ?
              )
        ''', (cutoff, cutoff))
        rows = [dict(zip([d[0] for d in cur.description], r)) for r in cur.fetchall()]
    except Exception:
        rows = []

    for row in rows:
        cur.execute(
            'SELECT id FROM capital_signals '
            'WHERE developer_id = ? AND signal_type = ? AND city = ? AND state = ?',
            (row['developer_id'], 'LENDER_ACTIVITY', row['city'], row['state'])
        )
        if not cur.fetchone():
            sid = str(uuid.uuid4())
            cur.execute(
                'INSERT INTO capital_signals '
                '(id, developer_id, signal_type, city, state, signal_strength) '
                'VALUES (?, ?, ?, ?, ?, ?)',
                (sid, row['developer_id'], 'LENDER_ACTIVITY', row['city'], row['state'], 55)
            )
            ingested += 1

    conn.commit()
    conn.close()
    return ingested


def calculate_capital_confidence(events, signals, has_dna_match=False, has_parcel_match=False):
    """
    Calculate confidence score for capital deployment prediction.
    Formula:
      (loan_signal * 25) + (equity_signal * 20) + (jv_signal * 15)
      + (developer_dna_match * 10) + (parcel_probability_match * 10)
    Capped at 100.
    """
    score = 0

    # Event-based scoring
    event_types_seen = set()
    for e in events:
        etype = e.get('event_type', '')
        if etype not in event_types_seen:
            score += EVENT_WEIGHTS.get(etype, 10)
            event_types_seen.add(etype)

    # Signal corroboration bonus
    signal_types_seen = set(s.get('signal_type', '') for s in signals)
    if len(signal_types_seen) >= 2:
        score += 10  # multiple signal sources bonus

    # DNA match bonus
    if has_dna_match:
        score += 10

    # Parcel match bonus
    if has_parcel_match:
        score += 10

    return min(score, 100)


def _format_amount(amount):
    """Format a dollar amount for display."""
    if not amount:
        return None
    if amount >= 1_000_000:
        return f"${amount / 1_000_000:.0f}M"
    if amount >= 1_000:
        return f"${amount / 1_000:.0f}K"
    return f"${amount:.0f}"


def generate_capital_reasoning(developer_name, city, state, events, signals):
    """Generate a human-readable explanation of the capital prediction."""
    event_labels = {
        'CONSTRUCTION_LOAN': 'construction loan filing',
        'LAND_ACQUISITION_LOAN': 'land acquisition financing',
        'DEBT_PLACEMENT': 'debt placement',
        'EQUITY_INVESTMENT': 'equity investment',
        'JOINT_VENTURE': 'joint venture formation',
        'FUND_DEPLOYMENT': 'fund deployment',
    }

    event_types = list({e.get('event_type') for e in events if e.get('event_type')})
    labels = [event_labels.get(t, t) for t in event_types]

    # Find max loan amount
    amounts = [e.get('loan_amount') for e in events if e.get('loan_amount')]
    amount_str = ''
    if amounts:
        max_amount = max(amounts)
        amount_str = f" with estimated capital of {_format_amount(max_amount)}"

    if len(labels) == 0:
        detail = 'capital activity'
    elif len(labels) == 1:
        detail = labels[0]
    else:
        detail = ', '.join(labels[:-1]) + ' and ' + labels[-1]

    return (
        f"{developer_name} shows capital deployment signals in "
        f"{city}, {state} including {detail}{amount_str}."
    )


def analyze_capital_signals():
    """
    Core analysis: group capital events and signals by developer+market
    within 90-day window and generate predictions.
    Returns list of new predictions created.
    """
    conn = get_db()
    cur = conn.cursor()
    cutoff = (datetime.utcnow() - timedelta(days=90)).isoformat()

    # Fetch recent capital events
    try:
        cur.execute('''
            SELECT ce.id, ce.developer_id, ce.company_name, ce.event_type,
                   ce.city, ce.state, ce.loan_amount, ce.lender_name,
                   ce.related_project, ce.source, ce.created_at,
                   d.developer_name
            FROM capital_events ce
            LEFT JOIN developers d ON ce.developer_id = d.id
            WHERE ce.created_at >= ?
            ORDER BY ce.developer_id, ce.city, ce.state
        ''', (cutoff,))
        cols = [d[0] for d in cur.description]
        all_events = [dict(zip(cols, r)) for r in cur.fetchall()]
    except Exception:
        all_events = []

    # Fetch recent capital signals
    try:
        cur.execute('''
            SELECT cs.id, cs.developer_id, cs.signal_type, cs.city, cs.state,
                   cs.signal_strength, cs.created_at
            FROM capital_signals cs
            WHERE cs.created_at >= ?
        ''', (cutoff,))
        cols = [d[0] for d in cur.description]
        all_signals = [dict(zip(cols, r)) for r in cur.fetchall()]
    except Exception:
        all_signals = []

    # Group events by developer + city + state
    event_groups = defaultdict(list)
    for ev in all_events:
        key = (ev['developer_id'], ev['city'], ev['state'])
        event_groups[key].append(ev)

    # Group signals by developer + city + state
    signal_groups = defaultdict(list)
    for sig in all_signals:
        key = (sig['developer_id'], sig['city'], sig['state'])
        signal_groups[key].append(sig)

    # Combine keys from both events and signals
    all_keys = set(event_groups.keys()) | set(signal_groups.keys())

    new_predictions = []

    for key in all_keys:
        dev_id, city, state = key
        events = event_groups.get(key, [])
        signals = signal_groups.get(key, [])

        # Need at least 1 capital event to generate a prediction
        if not events:
            continue

        developer_name = events[0].get('developer_name') or events[0].get('company_name') or 'Unknown Developer'

        # Check for DNA match
        has_dna_match = False
        try:
            cur.execute(
                'SELECT id FROM developer_dna_profiles WHERE developer_id = ?',
                (dev_id,)
            )
            has_dna_match = cur.fetchone() is not None
        except Exception:
            pass

        # Check for parcel probability match
        has_parcel_match = False
        try:
            cur.execute(
                'SELECT id FROM parcel_development_probability '
                'WHERE city = ? AND state = ? AND probability_score >= 60',
                (city, state)
            )
            has_parcel_match = cur.fetchone() is not None
        except Exception:
            pass

        confidence = calculate_capital_confidence(events, signals, has_dna_match, has_parcel_match)
        reasoning = generate_capital_reasoning(developer_name, city, state, events, signals)

        # Determine primary event type and estimated amount
        primary_event_type = events[0].get('event_type', 'CONSTRUCTION_LOAN')
        amounts = [e.get('loan_amount') for e in events if e.get('loan_amount')]
        estimated_amount = max(amounts) if amounts else None

        # Check if prediction already exists
        cur.execute(
            'SELECT id FROM capital_predictions '
            'WHERE developer_id = ? AND predicted_city = ? AND predicted_state = ?',
            (dev_id, city, state)
        )
        existing = cur.fetchone()

        pid = str(uuid.uuid4())
        if existing:
            cur.execute(
                'UPDATE capital_predictions '
                'SET capital_event_type = ?, estimated_capital_amount = ?, '
                'confidence_score = ?, reasoning = ?, created_at = ? '
                'WHERE developer_id = ? AND predicted_city = ? AND predicted_state = ?',
                (primary_event_type, estimated_amount, confidence, reasoning,
                 datetime.utcnow().isoformat(), dev_id, city, state)
            )
            pid = existing[0]
        else:
            cur.execute(
                'INSERT INTO capital_predictions '
                '(id, developer_id, predicted_city, predicted_state, '
                'capital_event_type, estimated_capital_amount, confidence_score, reasoning) '
                'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                (pid, dev_id, city, state, primary_event_type, estimated_amount,
                 confidence, reasoning)
            )

        new_predictions.append({
            'id': pid,
            'developer_id': dev_id,
            'developer_name': developer_name,
            'city': city,
            'state': state,
            'capital_event': primary_event_type,
            'estimated_amount': estimated_amount,
            'confidence': confidence,
            'reasoning': reasoning,
            'is_update': bool(existing),
        })

        # Log intelligence feed event for new predictions
        if not existing:
            try:
                from app import log_intelligence_event
                amount_display = _format_amount(estimated_amount) if estimated_amount else ''
                event_label = primary_event_type.replace('_', ' ').title()
                desc = f"{event_label}"
                if amount_display:
                    desc += f" — {amount_display}"
                desc += f". {reasoning}"
                log_intelligence_event(
                    event_type='CAPITAL_FLOW',
                    title=f'Capital Deployment Detected: {developer_name}',
                    description=desc,
                    city=city,
                    state=state,
                    related_entity=developer_name,
                    entity_id=pid,
                )
            except Exception as e:
                print(f"[CapitalFlowEngine] Feed event error: {e}")

    conn.commit()
    conn.close()
    return new_predictions
