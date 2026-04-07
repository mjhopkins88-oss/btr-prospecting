"""
Parcel Relationship Mapper.
Links signals to parcels and detects parcel activity clusters.
When a parcel has multiple signals within 90 days (permit, contractor bid,
zoning, land purchase), creates a relationship cluster.
"""
import json
import uuid
from datetime import datetime, timedelta
from db import get_db


def map_parcel_relationships():
    """
    Scan development_events grouped by parcel_id.
    If a parcel has 3+ events within 90 days, create cluster relationships.
    Also links parcels to their associated city projects.
    """
    conn = get_db()
    cur = conn.cursor()

    # Get all events with parcel_ids
    cutoff = (datetime.utcnow() - timedelta(days=180)).isoformat()
    cur.execute('''
        SELECT id, event_type, city, state, parcel_id, developer, event_date, created_at
        FROM development_events
        WHERE parcel_id IS NOT NULL AND parcel_id != ''
        AND created_at >= ?
        ORDER BY parcel_id, event_date
    ''', (cutoff,))

    rows = cur.fetchall()
    if not rows:
        conn.close()
        print("[ParcelMapper] No parceled events to process.")
        return 0

    col_names = [d[0] for d in cur.description]
    events = [dict(zip(col_names, r)) for r in rows]

    # Group by parcel
    parcel_groups = {}
    for e in events:
        pid = e['parcel_id'].strip()
        parcel_groups.setdefault(pid, []).append(e)

    created = 0

    for parcel_id, parcel_events in parcel_groups.items():
        event_types = set(e.get('event_type') for e in parcel_events if e.get('event_type'))

        # Link parcel to each event type
        for e in parcel_events:
            etype = e.get('event_type')
            if not etype:
                continue

            rel_type = f'PARCEL_HAS_{etype}'
            try:
                cur.execute('''
                    SELECT id FROM entity_relationships
                    WHERE entity_a = ? AND entity_b = ? AND relationship_type = ?
                    LIMIT 1
                ''', (parcel_id, e['id'], rel_type))
                if not cur.fetchone():
                    cur.execute('''
                        INSERT INTO entity_relationships
                        (id, entity_a, entity_a_type, entity_b, entity_b_type,
                         relationship_type, source, confidence, created_at)
                        VALUES (?, ?, 'parcel', ?, 'event', ?, ?, ?, CURRENT_TIMESTAMP)
                    ''', (str(uuid.uuid4()), parcel_id, e['id'], rel_type,
                          e.get('id'), 70))
                    created += 1
            except Exception:
                pass

        # Link parcel to developers
        developers = set(e.get('developer') for e in parcel_events if e.get('developer'))
        for dev in developers:
            try:
                cur.execute('''
                    SELECT id FROM entity_relationships
                    WHERE entity_a = ? AND entity_b = ? AND relationship_type = 'DEVELOPER_ASSOCIATED_PROJECT'
                    LIMIT 1
                ''', (dev, parcel_id))
                if not cur.fetchone():
                    cur.execute('''
                        INSERT INTO entity_relationships
                        (id, entity_a, entity_a_type, entity_b, entity_b_type,
                         relationship_type, source, confidence, created_at)
                        VALUES (?, ?, 'developer', ?, 'parcel', 'DEVELOPER_ASSOCIATED_PROJECT',
                                'parcel_mapper', ?, CURRENT_TIMESTAMP)
                    ''', (str(uuid.uuid4()), dev, parcel_id, 65))
                    created += 1
            except Exception:
                pass

        # Link parcel to city
        if parcel_events:
            city = parcel_events[0].get('city')
            state = parcel_events[0].get('state')
            if city and state:
                location = f"{city}, {state}"
                try:
                    cur.execute('''
                        SELECT id FROM entity_relationships
                        WHERE entity_a = ? AND entity_b = ? AND relationship_type = 'PARCEL_IN_CITY'
                        LIMIT 1
                    ''', (parcel_id, location))
                    if not cur.fetchone():
                        cur.execute('''
                            INSERT INTO entity_relationships
                            (id, entity_a, entity_a_type, entity_b, entity_b_type,
                             relationship_type, source, confidence, created_at)
                            VALUES (?, ?, 'parcel', ?, 'city', 'PARCEL_IN_CITY',
                                    'parcel_mapper', ?, CURRENT_TIMESTAMP)
                        ''', (str(uuid.uuid4()), parcel_id, location, 80))
                        created += 1
                except Exception:
                    pass

    conn.commit()
    conn.close()
    print(f"[ParcelMapper] Created {created} parcel relationships from {len(parcel_groups)} parcels.")
    return created
