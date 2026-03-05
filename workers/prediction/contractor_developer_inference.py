"""
Contractor Developer Inference.
Infers likely developers when contractor activity appears on a parcel
based on historical contractor-developer relationships.
"""
import json
from datetime import datetime

from db import get_db


def infer_developer_for_parcel(cur, parcel_id):
    """
    Given a parcel with contractor activity, infer the most likely developer.
    Returns dict with developer_name, confidence, reasoning or None.
    """
    # Get contractors active on this parcel
    cur.execute('''
        SELECT DISTINCT ca.firm_id, cf.firm_name, cf.firm_type
        FROM contractor_activity ca
        JOIN contractor_firms cf ON cf.id = ca.firm_id
        WHERE ca.parcel_id = ? AND ca.firm_id IS NOT NULL
    ''', (parcel_id,))
    contractors = cur.fetchall()

    if not contractors:
        return None

    best_match = None
    best_strength = 0

    for firm_id, firm_name, firm_type in contractors:
        # Find strongest developer relationship for this contractor
        cur.execute('''
            SELECT cdr.developer_id, d.developer_name,
                   cdr.relationship_strength, cdr.project_count
            FROM contractor_developer_relationships cdr
            JOIN developers d ON d.id = cdr.developer_id
            WHERE cdr.contractor_id = ?
            ORDER BY cdr.relationship_strength DESC
            LIMIT 1
        ''', (firm_id,))
        rel = cur.fetchone()

        if rel and rel[2] > best_strength:
            best_strength = rel[2]
            best_match = {
                'developer_id': rel[0],
                'developer_name': rel[1],
                'contractor_name': firm_name,
                'contractor_type': firm_type,
                'relationship_strength': rel[2],
                'project_count': rel[3],
            }

    if not best_match:
        return None

    # Build confidence from relationship strength
    confidence = min(100, best_match['relationship_strength'] + 10)

    # Build reasoning
    reasoning_parts = []
    reasoning_parts.append(
        f"{best_match['contractor_name']} ({best_match['contractor_type']}) "
        f"active on parcel"
    )
    reasoning_parts.append(
        f"Historically worked with {best_match['developer_name']} "
        f"on {best_match['project_count']} projects"
    )
    reasoning_parts.append(
        f"Relationship strength: {best_match['relationship_strength']}%"
    )

    return {
        'developer_name': best_match['developer_name'],
        'developer_id': best_match['developer_id'],
        'confidence': confidence,
        'reasoning': '. '.join(reasoning_parts),
        'contractor_firms': [best_match['contractor_name']],
    }


def infer_developers_for_all_parcels():
    """
    Run developer inference for all parcels with contractor activity.
    Returns list of inference results.
    """
    print(f"[Developer Inference] START — {datetime.utcnow().isoformat()}")

    conn = get_db()
    cur = conn.cursor()

    # Get distinct parcels with contractor activity
    cur.execute('''
        SELECT DISTINCT parcel_id FROM contractor_activity
        WHERE parcel_id IS NOT NULL
    ''')
    parcels = [r[0] for r in cur.fetchall()]

    inferences = []
    for parcel_id in parcels:
        result = infer_developer_for_parcel(cur, parcel_id)
        if result:
            result['parcel_id'] = parcel_id
            inferences.append(result)

    conn.close()

    print(f"[Developer Inference] COMPLETE — {len(inferences)} inferences made")
    return inferences


def get_contractor_firms_for_city(cur, city, state):
    """
    Get all contractor firms active in a city/state.
    Used for enriching prediction API responses.
    """
    cur.execute('''
        SELECT DISTINCT cf.firm_name
        FROM contractor_activity ca
        JOIN contractor_firms cf ON cf.id = ca.firm_id
        JOIN development_events de ON ca.parcel_id = de.parcel_id
        WHERE de.city = ? AND de.state = ?
    ''', (city, state))
    return [r[0] for r in cur.fetchall()]


def get_inferred_developer_for_city(cur, city, state):
    """
    Get the strongest developer inference for a city/state based on
    contractor relationships.
    Returns dict with developer_name, confidence, reasoning, firms or None.
    """
    # Get parcels in this city
    cur.execute('''
        SELECT DISTINCT de.parcel_id
        FROM development_events de
        WHERE de.city = ? AND de.state = ? AND de.parcel_id IS NOT NULL
    ''', (city, state))
    parcels = [r[0] for r in cur.fetchall()]

    best_inference = None
    best_confidence = 0
    all_firms = set()

    for parcel_id in parcels:
        result = infer_developer_for_parcel(cur, parcel_id)
        if result:
            all_firms.update(result.get('contractor_firms', []))
            if result['confidence'] > best_confidence:
                best_confidence = result['confidence']
                best_inference = result

    if not best_inference:
        return None

    best_inference['contractor_firms'] = list(all_firms)
    return best_inference
