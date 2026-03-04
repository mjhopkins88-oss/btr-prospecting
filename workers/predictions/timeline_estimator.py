"""
Timeline Estimator.
Estimates expected construction start window based on the most advanced
development event stage detected for a prediction.
"""
from datetime import datetime, timedelta
from db import get_db


# Event stage → estimated months to construction start
STAGE_TIMELINES = {
    'LLC_CREATION':       (12, 18),
    'LAND_PURCHASE':      (9, 15),
    'ZONING_CASE':        (6, 12),
    'SUBDIVISION_PLAT':   (4, 8),
    'PERMIT_APPLICATION': (2, 4),
    'CONTRACTOR_BID':     (1, 3),
    'NEWS_MENTION':       (3, 12),  # too vague for tight estimate
}

# Stage advancement order (most advanced first)
STAGE_ORDER = [
    'CONTRACTOR_BID',
    'PERMIT_APPLICATION',
    'SUBDIVISION_PLAT',
    'ZONING_CASE',
    'LAND_PURCHASE',
    'LLC_CREATION',
    'NEWS_MENTION',
]


def estimate_timeline(city, state):
    """
    Look at development_events for a city/state and return the estimated
    construction window based on the most advanced event stage.

    Returns:
        str like "Construction likely in 4-8 months" or None
    """
    conn = get_db()
    cur = conn.cursor()
    cur.execute('''
        SELECT DISTINCT event_type FROM development_events
        WHERE city = ? AND state = ?
    ''', (city, state))
    rows = cur.fetchall()
    conn.close()

    if not rows:
        return None

    event_types = set(r[0] for r in rows if r[0])

    # Find the most advanced stage
    for stage in STAGE_ORDER:
        if stage in event_types:
            low, high = STAGE_TIMELINES[stage]
            return f"Construction likely in {low}-{high} months"

    return None


def estimate_timeline_from_events(event_types):
    """
    Given a list/set of event type strings, return the timeline estimate.
    Useful when you already have the event types and don't want a DB query.
    """
    if not event_types:
        return None

    types_set = set(event_types) if not isinstance(event_types, set) else event_types

    for stage in STAGE_ORDER:
        if stage in types_set:
            low, high = STAGE_TIMELINES[stage]
            return f"Construction likely in {low}-{high} months"

    return None
