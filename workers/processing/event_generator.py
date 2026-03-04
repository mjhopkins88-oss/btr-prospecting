"""
Event Generator Worker.
Converts raw signals (from li_signals and weighted_signals) into structured
development events in the development_events table.

Scans signal headlines and bodies for keyword patterns that indicate
specific development lifecycle events (land purchases, zoning cases,
subdivision plats, permit applications, etc.).
"""
import json
import re
import traceback
from datetime import datetime

from db import get_db, IntegrityError


# ---------------------------------------------------------------------------
# Keyword → event type mapping
# ---------------------------------------------------------------------------
EVENT_KEYWORDS = {
    'LAND_PURCHASE': [
        r'land\s+purchase', r'acre\s+purchase', r'sold\s+property',
        r'land\s+sale', r'land\s+acquisition', r'acquired\s+\d+\s+acres?',
        r'bought\s+\d+\s+acres?', r'land\s+deal', r'property\s+sale',
        r'parcel\s+sold', r'land\s+transaction',
    ],
    'LLC_CREATION': [
        r'llc\s+created', r'llc\s+filed', r'llc\s+registered',
        r'entity\s+formation', r'new\s+llc', r'development\s+llc',
        r'land\s+llc', r'property\s+llc',
    ],
    'ZONING_CASE': [
        r'rezoning', r'zoning\s+case', r'planning\s+commission',
        r'zoning\s+change', r'zoning\s+request', r'zoning\s+hearing',
        r'zoning\s+approval', r'zoning\s+amendment', r'rezone',
        r'land\s+use\s+change', r'conditional\s+use',
    ],
    'SUBDIVISION_PLAT': [
        r'final\s+plat', r'subdivision', r'plat\s+approval',
        r'preliminary\s+plat', r'plat\s+filed', r'plat\s+recorded',
        r'lot\s+division', r'subdivision\s+plat',
    ],
    'PERMIT_APPLICATION': [
        r'building\s+permit', r'permit\s+application', r'permit\s+filed',
        r'permit\s+issued', r'construction\s+permit', r'site\s+plan\s+approval',
        r'development\s+permit',
    ],
    'CONTRACTOR_BID': [
        r'contractor\s+bid', r'bid\s+solicitation', r'rfp\s+issued',
        r'construction\s+bid', r'general\s+contractor\s+selected',
    ],
    'NEWS_MENTION': [
        r'announced\s+plans?\s+to\s+build', r'plans?\s+to\s+develop',
        r'proposed\s+development', r'new\s+community',
        r'broke\s+ground', r'groundbreaking', r'construction\s+start',
    ],
}

# Pre-compile regexes for performance
_COMPILED_PATTERNS = {}
for event_type, patterns in EVENT_KEYWORDS.items():
    _COMPILED_PATTERNS[event_type] = [
        re.compile(p, re.IGNORECASE) for p in patterns
    ]


def _classify_text(text):
    """
    Classify text into zero or more event types.
    Returns list of (event_type, matched_keyword) tuples.
    """
    if not text:
        return []
    results = []
    for event_type, patterns in _COMPILED_PATTERNS.items():
        for pat in patterns:
            if pat.search(text):
                results.append((event_type, pat.pattern))
                break  # one match per event type is enough
    return results


def _extract_developer(text, raw_json=None):
    """Try to extract a developer/company name from signal data."""
    if raw_json:
        try:
            data = json.loads(raw_json) if isinstance(raw_json, str) else raw_json
            for key in ('company_name', 'developer', 'entity_name', 'company'):
                if data.get(key):
                    return data[key]
        except Exception:
            pass
    return None


def _extract_parcel_id(text, raw_json=None):
    """Try to extract a parcel ID from signal data."""
    # Look for common parcel ID patterns
    if text:
        match = re.search(r'parcel\s*(?:id|#|number)?\s*[:=]?\s*([A-Z0-9\-\.]{5,20})', text, re.IGNORECASE)
        if match:
            return match.group(1)
    if raw_json:
        try:
            data = json.loads(raw_json) if isinstance(raw_json, str) else raw_json
            if data.get('parcel_id'):
                return data['parcel_id']
        except Exception:
            pass
    return None


def generate_events_from_li_signals(batch_size=200):
    """
    Scan li_signals for unprocessed signals and generate development events.
    Uses a simple heuristic: if we haven't seen this signal URL+headline as
    an event source before, process it.
    """
    conn = get_db()
    cur = conn.cursor()

    # Get recent signals not yet converted to events
    cur.execute('''
        SELECT s.id, s.headline, s.body, s.url, s.city, s.state,
               s.raw_json, s.published_at, s.created_at
        FROM li_signals s
        WHERE NOT EXISTS (
            SELECT 1 FROM development_events de
            WHERE de.source = s.id
        )
        ORDER BY s.created_at DESC
        LIMIT ?
    ''', (batch_size,))
    signals = cur.fetchall()

    if not signals:
        print("[EventGenerator] No new signals to process.")
        conn.close()
        return 0

    # Get column names
    col_names = [d[0] for d in cur.description]
    created = 0

    for row in signals:
        sig = dict(zip(col_names, row))
        combined_text = ' '.join(filter(None, [sig.get('headline'), sig.get('body')]))
        classifications = _classify_text(combined_text)

        if not classifications:
            continue

        developer = _extract_developer(combined_text, sig.get('raw_json'))
        parcel_id = _extract_parcel_id(combined_text, sig.get('raw_json'))
        event_date = sig.get('published_at') or sig.get('created_at')

        for event_type, matched_keyword in classifications:
            try:
                import uuid
                cur.execute('''
                    INSERT INTO development_events
                    (id, event_type, city, state, parcel_id, developer,
                     event_date, source, metadata, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ''', (
                    str(uuid.uuid4()),
                    event_type,
                    sig.get('city'),
                    sig.get('state'),
                    parcel_id,
                    developer,
                    event_date,
                    sig.get('id'),  # source = signal ID
                    json.dumps({
                        'headline': sig.get('headline'),
                        'url': sig.get('url'),
                        'matched_keyword': matched_keyword,
                    }, default=str),
                ))
                created += 1
            except Exception as e:
                # Skip duplicates or other errors
                pass

    conn.commit()
    conn.close()
    print(f"[EventGenerator] Created {created} development events from {len(signals)} signals.")
    return created


def generate_events_from_weighted_signals(batch_size=200):
    """
    Also scan the existing weighted_signals table for development events.
    This bridges the legacy signal system into the new event framework.
    """
    conn = get_db()
    cur = conn.cursor()

    # Check if weighted_signals table exists
    try:
        cur.execute('''
            SELECT ws.id, ws.entity_name, ws.signal_text, ws.city, ws.state,
                   ws.created_at
            FROM weighted_signals ws
            WHERE NOT EXISTS (
                SELECT 1 FROM development_events de
                WHERE de.source = ('ws_' || CAST(ws.id AS TEXT))
            )
            ORDER BY ws.created_at DESC
            LIMIT ?
        ''', (batch_size,))
        signals = cur.fetchall()
    except Exception:
        conn.close()
        return 0

    if not signals:
        conn.close()
        return 0

    col_names = [d[0] for d in cur.description]
    created = 0

    for row in signals:
        sig = dict(zip(col_names, row))
        text = sig.get('signal_text') or ''
        classifications = _classify_text(text)

        if not classifications:
            continue

        developer = sig.get('entity_name')
        event_date = sig.get('created_at')

        for event_type, matched_keyword in classifications:
            try:
                import uuid
                cur.execute('''
                    INSERT INTO development_events
                    (id, event_type, city, state, parcel_id, developer,
                     event_date, source, metadata, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ''', (
                    str(uuid.uuid4()),
                    event_type,
                    sig.get('city'),
                    sig.get('state'),
                    None,  # no parcel from weighted_signals
                    developer,
                    event_date,
                    f"ws_{sig.get('id')}",
                    json.dumps({
                        'signal_text': text[:500],
                        'matched_keyword': matched_keyword,
                    }, default=str),
                ))
                created += 1
            except Exception:
                pass

    conn.commit()
    conn.close()
    print(f"[EventGenerator] Created {created} events from weighted_signals.")
    return created


def generate_all_events():
    """Run all event generation passes."""
    total = 0
    total += generate_events_from_li_signals()
    total += generate_events_from_weighted_signals()
    return total
