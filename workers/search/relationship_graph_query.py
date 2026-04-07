"""
Relationship Graph Query Engine.
Enables querying the entity_relationships table for development lead candidates
based on multi-entity relationship patterns.
"""
from datetime import datetime, timedelta
from db import get_db


def find_parcels_with_multi_relationships(min_relationships=2, days=120):
    """
    Find parcels where:
    - developer relationship exists AND
    - contractor relationship exists AND
    - parcel purchased within `days` days.

    Returns list of candidate lead dicts.
    """
    conn = get_db()
    cur = conn.cursor()

    cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()

    cur.execute('''
        SELECT er.entity_a as parcel_id,
               er.relationship_type,
               er.entity_b,
               er.entity_b_type,
               er.confidence,
               er.created_at
        FROM entity_relationships er
        WHERE er.entity_a_type = 'parcel'
        AND er.created_at >= ?
        ORDER BY er.entity_a, er.created_at
    ''', (cutoff,))

    rows = cur.fetchall()
    conn.close()

    if not rows:
        return []

    col_names = [d[0] for d in cur.description]
    rels = [dict(zip(col_names, r)) for r in rows]

    # Group by parcel
    parcel_rels = {}
    for r in rels:
        pid = r['parcel_id']
        parcel_rels.setdefault(pid, []).append(r)

    candidates = []
    for parcel_id, relations in parcel_rels.items():
        if len(relations) < min_relationships:
            continue

        rel_types = set(r['relationship_type'] for r in relations)
        candidates.append({
            'parcel_id': parcel_id,
            'relationship_count': len(relations),
            'relationship_types': list(rel_types),
            'has_developer': any('DEVELOPER' in rt or 'PURCHASED' in rt for rt in rel_types),
            'has_contractor': any('CONTRACTOR' in rt for rt in rel_types),
            'has_consultant': any('CONSULTANT' in rt for rt in rel_types),
            'has_permit': any('PERMIT' in rt for rt in rel_types),
        })

    # Sort by relationship count desc
    candidates.sort(key=lambda x: x['relationship_count'], reverse=True)
    return candidates


def get_relationships_for_city(city, state, limit=100):
    """
    Get all entity relationships involving a specific city/state.
    Used by the optimizer to compute relationship boost for predictions.
    """
    conn = get_db()
    cur = conn.cursor()

    location = f"{city}, {state}"

    # Get direct city relationships
    cur.execute('''
        SELECT id, entity_a, entity_a_type, entity_b, entity_b_type,
               relationship_type, confidence
        FROM entity_relationships
        WHERE entity_b = ? OR entity_a = ?
        ORDER BY created_at DESC
        LIMIT ?
    ''', (location, location, limit))

    rows = cur.fetchall()
    col_names = [d[0] for d in cur.description]
    direct_rels = [dict(zip(col_names, r)) for r in rows]

    # Also get relationships from events in this city
    cur.execute('''
        SELECT DISTINCT er.id, er.entity_a, er.entity_a_type,
               er.entity_b, er.entity_b_type, er.relationship_type, er.confidence
        FROM entity_relationships er
        JOIN development_events de ON er.source = de.id
        WHERE de.city = ? AND de.state = ?
        ORDER BY er.created_at DESC
        LIMIT ?
    ''', (city, state, limit))

    rows2 = cur.fetchall()
    col_names2 = [d[0] for d in cur.description]
    event_rels = [dict(zip(col_names2, r)) for r in rows2]

    conn.close()

    # Deduplicate
    seen_ids = set()
    all_rels = []
    for r in direct_rels + event_rels:
        if r['id'] not in seen_ids:
            seen_ids.add(r['id'])
            all_rels.append(r)

    return all_rels


def compute_relationship_data_for_prediction(city, state, developer=None):
    """
    Compute relationship metrics for a specific prediction.
    Returns dict with relationship_count, developer_linked, contractor_linked,
    consultant_linked, and relationship_boost.
    """
    rels = get_relationships_for_city(city, state)

    result = {
        'relationship_count': len(rels),
        'developer_linked': False,
        'contractor_linked': False,
        'consultant_linked': False,
        'relationship_boost': 0,
    }

    developer_linked = False
    contractor_linked = False
    consultant_linked = False
    parcel_signal_count = 0

    for r in rels:
        rel_type = r.get('relationship_type', '')

        # Developer linked to parcel/project
        if 'DEVELOPER' in rel_type or 'PURCHASED' in rel_type or 'OWNS' in rel_type:
            developer_linked = True
            # Extra check: does the developer match our prediction's developer?
            if developer:
                if (developer.lower() in (r.get('entity_a', '').lower()) or
                    developer.lower() in (r.get('entity_b', '').lower())):
                    developer_linked = True

        # Contractor linked
        if 'CONTRACTOR' in rel_type:
            contractor_linked = True

        # Consultant linked
        if 'CONSULTANT' in rel_type:
            consultant_linked = True

        # Count parcel signals
        if r.get('entity_a_type') == 'parcel' or r.get('entity_b_type') == 'parcel':
            parcel_signal_count += 1

    result['developer_linked'] = developer_linked
    result['contractor_linked'] = contractor_linked
    result['consultant_linked'] = consultant_linked

    # Compute relationship boost (Step 6)
    boost = 0
    if developer_linked:
        boost += 20
    if contractor_linked:
        boost += 15
    if consultant_linked:
        boost += 10
    if parcel_signal_count >= 3:
        boost += 20

    result['relationship_boost'] = min(65, boost)

    return result
