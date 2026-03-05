"""
Contractor Intelligence Analyzer.
Analyzes contractor_activity records to identify development signals on parcels.
Detects activity clusters that indicate early-stage development.
"""
import json
import uuid
from collections import defaultdict
from datetime import datetime

from db import get_db

# Activity types that indicate contractor involvement in development
CONTRACTOR_SIGNAL_TYPES = {
    'SITE_PLAN_PREP', 'ENGINEERING_PLAN_SUBMISSION', 'CONTRACTOR_BID',
    'SURVEY_WORK', 'UTILITY_EXTENSION', 'SITE_GRADING',
}

# Event types from development_events that map to contractor activity
EVENT_TO_ACTIVITY = {
    'CONTRACTOR_BID': 'CONTRACTOR_BID',
    'ENGINEERING_PLAN': 'ENGINEERING_PLAN_SUBMISSION',
    'SURVEY_PERMIT': 'SURVEY_WORK',
    'SITE_PLAN': 'SITE_PLAN_PREP',
    'UTILITY_PLAN': 'UTILITY_EXTENSION',
    'GRADING_PERMIT': 'SITE_GRADING',
}


def _ingest_contractor_firms_from_events(cur):
    """
    Auto-populate contractor_firms from development_events metadata.
    Looks for contractor/engineering/consultant firm names in event metadata.
    """
    cur.execute('''
        SELECT DISTINCT metadata FROM development_events
        WHERE metadata IS NOT NULL
        AND event_type IN ('CONTRACTOR_BID', 'ENGINEERING_PLAN', 'SURVEY_PERMIT',
                           'SITE_PLAN', 'UTILITY_PLAN', 'GRADING_PERMIT',
                           'CONSULTANT_HIRE')
    ''')
    rows = cur.fetchall()

    firms_added = 0
    for row in rows:
        try:
            meta = json.loads(row[0]) if isinstance(row[0], str) else row[0]
            firm_name = (meta.get('contractor') or meta.get('firm') or
                        meta.get('engineer') or meta.get('consultant') or
                        meta.get('company'))
            if not firm_name:
                continue

            cur.execute('SELECT id FROM contractor_firms WHERE firm_name = ?', (firm_name,))
            if cur.fetchone():
                continue

            firm_type = _infer_firm_type(meta)
            cur.execute('''
                INSERT INTO contractor_firms (id, firm_name, firm_type)
                VALUES (?, ?, ?)
            ''', (str(uuid.uuid4()), firm_name, firm_type))
            firms_added += 1
        except Exception:
            pass

    return firms_added


def _infer_firm_type(meta):
    """Infer firm type from event metadata."""
    event_type = meta.get('event_type', '').upper()
    description = str(meta.get('description', '')).upper()

    if 'ENGINEER' in description or 'ENGINEERING' in description:
        return 'CIVIL_ENGINEERING'
    if 'SURVEY' in description or 'SURVEYOR' in description:
        return 'SURVEYOR'
    if 'ARCHITECT' in description:
        return 'ARCHITECTURE'
    if 'UTILITY' in description:
        return 'UTILITY_CONTRACTOR'
    return 'GENERAL_CONTRACTOR'


def _ingest_activity_from_events(cur):
    """
    Populate contractor_activity from development_events that involve
    contractor/consultant signals.
    """
    contractor_event_types = list(EVENT_TO_ACTIVITY.keys()) + ['CONSULTANT_HIRE']
    placeholders = ','.join(['?' for _ in contractor_event_types])

    cur.execute(f'''
        SELECT id, event_type, parcel_id, developer, event_date, source, metadata
        FROM development_events
        WHERE event_type IN ({placeholders})
        AND parcel_id IS NOT NULL
    ''', contractor_event_types)
    events = cur.fetchall()

    ingested = 0
    for event_id, event_type, parcel_id, developer, event_date, source, metadata in events:
        activity_type = EVENT_TO_ACTIVITY.get(event_type, event_type)

        # Try to find associated firm
        firm_id = None
        if metadata:
            try:
                meta = json.loads(metadata) if isinstance(metadata, str) else metadata
                firm_name = (meta.get('contractor') or meta.get('firm') or
                            meta.get('engineer') or meta.get('consultant'))
                if firm_name:
                    cur.execute('SELECT id FROM contractor_firms WHERE firm_name = ?', (firm_name,))
                    firm_row = cur.fetchone()
                    if firm_row:
                        firm_id = firm_row[0]
            except Exception:
                pass

        # Check if already ingested (by matching parcel + activity_type + date)
        cur.execute('''
            SELECT id FROM contractor_activity
            WHERE parcel_id = ? AND activity_type = ? AND activity_date = ?
        ''', (parcel_id, activity_type, event_date))
        if cur.fetchone():
            continue

        cur.execute('''
            INSERT INTO contractor_activity
            (id, firm_id, parcel_id, activity_type, activity_date, source, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (str(uuid.uuid4()), firm_id, parcel_id, activity_type,
              event_date, source, metadata))
        ingested += 1

        # Log to intelligence feed
        try:
            from app import log_intelligence_event
            log_intelligence_event(
                event_type='CONTRACTOR_ACTIVITY',
                title=f"NEW CONTRACTOR ACTIVITY",
                description=f"{activity_type} detected on parcel {parcel_id}",
                related_entity=str(firm_id),
                entity_id=parcel_id,
            )
        except Exception:
            pass

    return ingested


def detect_parcel_activity_clusters(cur):
    """
    Detect parcels with multiple contractor activity signals.
    A cluster = 2+ distinct activity types on same parcel.
    Returns list of (parcel_id, activity_count, activities).
    """
    cur.execute('''
        SELECT parcel_id, COUNT(DISTINCT activity_type) as type_count,
               COUNT(*) as total_count
        FROM contractor_activity
        WHERE parcel_id IS NOT NULL
        GROUP BY parcel_id
        HAVING COUNT(DISTINCT activity_type) >= 2
        ORDER BY type_count DESC
    ''')
    clusters = []
    for row in cur.fetchall():
        parcel_id = row[0]
        # Get the activity types
        cur.execute('''
            SELECT DISTINCT activity_type FROM contractor_activity
            WHERE parcel_id = ?
        ''', (parcel_id,))
        activities = [r[0] for r in cur.fetchall()]
        clusters.append({
            'parcel_id': parcel_id,
            'activity_count': row[1],
            'total_signals': row[2],
            'activities': activities,
        })
    return clusters


def run_contractor_analysis():
    """
    Main entry point: ingest contractor data from events,
    detect activity clusters, log findings.
    """
    print(f"[Contractor Analyzer] START — {datetime.utcnow().isoformat()}")

    conn = get_db()
    cur = conn.cursor()

    firms_added = _ingest_contractor_firms_from_events(cur)
    print(f"[Contractor Analyzer] Ingested {firms_added} new contractor firms")

    ingested = _ingest_activity_from_events(cur)
    print(f"[Contractor Analyzer] Ingested {ingested} new activity records")

    clusters = detect_parcel_activity_clusters(cur)
    print(f"[Contractor Analyzer] Detected {len(clusters)} activity clusters")

    # Log cluster detections
    for cluster in clusters:
        cur.execute('''
            INSERT INTO contractor_intelligence_log
            (id, parcel_id, activity_detected, confidence)
            VALUES (?, ?, ?, ?)
        ''', (
            str(uuid.uuid4()),
            cluster['parcel_id'],
            ','.join(cluster['activities']),
            min(100, 40 + cluster['activity_count'] * 15),
        ))

    conn.commit()
    conn.close()

    print(f"[Contractor Analyzer] COMPLETE")
    return {
        'firms_added': firms_added,
        'activities_ingested': ingested,
        'clusters': len(clusters),
    }
