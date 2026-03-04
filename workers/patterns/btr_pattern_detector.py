"""
BTR Pattern Detector.
Scans the development_events table for the classic BTR pre-development pattern:

    LAND_PURCHASE -> ZONING_CASE -> SUBDIVISION_PLAT

If these three events occur within 90 days in the same city (or same parcel_id),
a predicted project is generated with a confidence score.

Also includes a confirmation engine that updates predicted_projects when
later signals confirm the development (PERMIT_APPLICATION, NEWS_MENTION, etc.).
"""
import json
import uuid
import traceback
from datetime import datetime, timedelta

from db import get_db, IntegrityError


# The core BTR pattern
REQUIRED_EVENTS = ['LAND_PURCHASE', 'ZONING_CASE', 'SUBDIVISION_PLAT']
PATTERN_LABEL = 'LAND_PURCHASE -> ZONING_CASE -> SUBDIVISION_PLAT'
MAX_WINDOW_DAYS = 90

# Confirmation event types
CONFIRMATION_EVENTS = ['PERMIT_APPLICATION', 'NEWS_MENTION', 'CONTRACTOR_BID']


def _compute_confidence(events, has_parcel_match, has_developer_match, window_days):
    """
    Compute confidence score for a predicted development.

    base_score = 50
    +20 if parcel_id matches across events
    +15 if developer appears in multiple events
    +15 if events occurred within 60 days
    Clamped to [0, 100].
    """
    score = 50

    if has_parcel_match:
        score += 20

    if has_developer_match:
        score += 15

    if window_days <= 60:
        score += 15

    return max(0, min(100, score))


def _get_primary_developer(events):
    """Find the most common developer name across a set of events."""
    developers = {}
    for e in events:
        dev = e.get('developer')
        if dev:
            dev_clean = dev.strip()
            developers[dev_clean] = developers.get(dev_clean, 0) + 1
    if not developers:
        return None
    return max(developers, key=developers.get)


def detect_patterns():
    """
    Scan development_events grouped by city+state (and parcel_id where available).
    Detect the LAND_PURCHASE -> ZONING_CASE -> SUBDIVISION_PLAT pattern.
    Returns list of detected patterns as dicts.
    """
    conn = get_db()
    cur = conn.cursor()

    # Get all events from the last 180 days (generous window for grouping)
    cutoff = (datetime.utcnow() - timedelta(days=180)).isoformat()
    cur.execute('''
        SELECT id, event_type, city, state, parcel_id, developer,
               event_date, source, metadata, created_at
        FROM development_events
        WHERE created_at >= ?
        ORDER BY event_date ASC
    ''', (cutoff,))

    rows = cur.fetchall()
    if not rows:
        conn.close()
        print("[PatternDetector] No recent events to analyze.")
        return []

    col_names = [d[0] for d in cur.description]
    events = [dict(zip(col_names, r)) for r in rows]

    # Group events by (city, state) and by parcel_id
    city_groups = {}
    parcel_groups = {}

    for e in events:
        city_key = (
            (e.get('city') or '').strip().lower(),
            (e.get('state') or '').strip().upper()
        )
        if city_key[0]:
            city_groups.setdefault(city_key, []).append(e)

        parcel = e.get('parcel_id')
        if parcel:
            parcel_groups.setdefault(parcel.strip(), []).append(e)

    detected = []

    # Check parcel-based groups first (higher confidence)
    for parcel_id, group_events in parcel_groups.items():
        result = _check_group_for_pattern(group_events, has_parcel_match=True)
        if result:
            result['parcel_id'] = parcel_id
            detected.append(result)

    # Check city-based groups (avoid duplicating parcel-based detections)
    detected_cities = set()
    for (city, state), group_events in city_groups.items():
        result = _check_group_for_pattern(group_events, has_parcel_match=False)
        if result:
            # Skip if we already detected this via parcel matching in the same city
            city_key = f"{city}|{state}"
            if city_key not in detected_cities:
                detected.append(result)
                detected_cities.add(city_key)

    conn.close()
    print(f"[PatternDetector] Detected {len(detected)} BTR development patterns.")
    return detected


def _check_group_for_pattern(events, has_parcel_match=False):
    """
    Check if a group of events contains all three required event types
    within the 90-day window.
    """
    type_events = {}
    for e in events:
        etype = e.get('event_type')
        if etype in REQUIRED_EVENTS:
            type_events.setdefault(etype, []).append(e)

    # Must have all three event types
    if len(type_events) < len(REQUIRED_EVENTS):
        return None

    # Get earliest and latest event dates across the pattern
    all_dates = []
    for etype in REQUIRED_EVENTS:
        for e in type_events[etype]:
            date_val = e.get('event_date')
            if date_val:
                try:
                    if isinstance(date_val, str):
                        dt = datetime.fromisoformat(date_val.replace('Z', '+00:00').replace('+00:00', ''))
                    else:
                        dt = date_val
                    all_dates.append(dt)
                except Exception:
                    pass

    if len(all_dates) < 2:
        return None

    earliest = min(all_dates)
    latest = max(all_dates)
    window_days = (latest - earliest).days

    if window_days > MAX_WINDOW_DAYS:
        return None

    # Pattern detected — compute confidence
    all_pattern_events = []
    for etype in REQUIRED_EVENTS:
        all_pattern_events.extend(type_events[etype])

    developer = _get_primary_developer(all_pattern_events)
    developers_set = set(
        e.get('developer', '').strip().lower()
        for e in all_pattern_events if e.get('developer')
    )
    has_developer_match = len(developers_set) >= 1 and any(
        sum(1 for e in all_pattern_events
            if (e.get('developer') or '').strip().lower() == d) >= 2
        for d in developers_set
    )

    confidence = _compute_confidence(
        all_pattern_events, has_parcel_match, has_developer_match, window_days
    )

    # Use first event's city/state
    city = all_pattern_events[0].get('city')
    state = all_pattern_events[0].get('state')

    return {
        'city': city,
        'state': state,
        'developer': developer,
        'confidence': confidence,
        'window_days': window_days,
        'pattern_detected': PATTERN_LABEL,
        'event_count': len(all_pattern_events),
        'event_ids': [e['id'] for e in all_pattern_events],
    }


def store_predictions(patterns):
    """
    Store detected patterns as predicted_projects.
    Skips duplicates (same city+state+developer already predicted and unconfirmed).
    """
    if not patterns:
        return 0

    conn = get_db()
    cur = conn.cursor()
    stored = 0

    for pat in patterns:
        city = pat.get('city')
        state = pat.get('state')
        developer = pat.get('developer')
        signal_count = pat.get('event_count', 0)

        # Check for existing unconfirmed prediction
        cur.execute('''
            SELECT id FROM predicted_projects
            WHERE city = ? AND state = ? AND COALESCE(developer, '') = COALESCE(?, '')
            AND confirmed = 0
        ''', (city, state, developer))

        existing = cur.fetchone()
        if existing:
            # Update confidence and signal_count
            cur.execute('''
                UPDATE predicted_projects
                SET confidence = MAX(confidence, ?),
                    signal_count = ?,
                    prediction_date = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (pat['confidence'], signal_count, existing[0]))
        else:
            try:
                cur.execute('''
                    INSERT INTO predicted_projects
                    (id, city, state, developer, prediction_date, confidence,
                     pattern_detected, confirmed, signal_count, created_at)
                    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, ?, ?, 0, ?, CURRENT_TIMESTAMP)
                ''', (
                    str(uuid.uuid4()),
                    city, state, developer,
                    pat['confidence'],
                    pat['pattern_detected'],
                    signal_count,
                ))
                stored += 1
            except Exception as e:
                print(f"[PatternDetector] Error storing prediction: {e}")

    conn.commit()
    conn.close()
    print(f"[PatternDetector] Stored {stored} new predictions.")
    return stored


def confirm_predictions():
    """
    Confirmation Engine.
    Check if any unconfirmed predicted_projects now have confirming events
    (PERMIT_APPLICATION, NEWS_MENTION confirming construction, CONTRACTOR_BID).
    If so, set confirmed = true.
    """
    conn = get_db()
    cur = conn.cursor()

    # Get unconfirmed predictions
    cur.execute('''
        SELECT id, city, state, developer
        FROM predicted_projects
        WHERE confirmed = 0
    ''')
    predictions = cur.fetchall()

    if not predictions:
        conn.close()
        return 0

    col_names = [d[0] for d in cur.description]
    confirmed_count = 0

    for row in predictions:
        pred = dict(zip(col_names, row))
        city = pred.get('city')
        state = pred.get('state')

        # Look for confirming events in the same city/state
        placeholders = ', '.join(['?'] * len(CONFIRMATION_EVENTS))
        params = list(CONFIRMATION_EVENTS) + [city, state]
        cur.execute(f'''
            SELECT COUNT(*) FROM development_events
            WHERE event_type IN ({placeholders})
            AND city = ? AND state = ?
        ''', params)

        count = cur.fetchone()[0]
        if count > 0:
            cur.execute('''
                UPDATE predicted_projects SET confirmed = 1 WHERE id = ?
            ''', (pred['id'],))
            confirmed_count += 1
            print(f"[Confirmation] Confirmed prediction: {city}, {state}")

    conn.commit()
    conn.close()
    print(f"[Confirmation] Confirmed {confirmed_count}/{len(predictions)} predictions.")
    return confirmed_count


def run_detection():
    """Full detection pipeline: detect patterns, store predictions, confirm existing."""
    patterns = detect_patterns()
    stored = store_predictions(patterns)
    confirmed = confirm_predictions()
    return {
        'patterns_detected': len(patterns),
        'predictions_stored': stored,
        'predictions_confirmed': confirmed,
    }
