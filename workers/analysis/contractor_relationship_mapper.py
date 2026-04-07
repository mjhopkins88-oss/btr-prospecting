"""
Contractor Relationship Mapper.
Analyzes historical projects to build relationships between
contractor firms and developers.
"""
import uuid
from datetime import datetime

from db import get_db


def _find_contractor_developer_pairs(cur):
    """
    Find contractor-developer pairs by matching contractor_activity parcels
    with development_events on the same parcels.
    """
    cur.execute('''
        SELECT ca.firm_id, de.developer, COUNT(*) as co_occurrence
        FROM contractor_activity ca
        JOIN development_events de
            ON ca.parcel_id = de.parcel_id
        WHERE ca.firm_id IS NOT NULL
        AND de.developer IS NOT NULL AND de.developer != ''
        GROUP BY ca.firm_id, de.developer
        ORDER BY co_occurrence DESC
    ''')
    return cur.fetchall()


def _find_pairs_from_entity_relationships(cur):
    """
    Also check entity_relationships table for contractor-developer links.
    """
    try:
        cur.execute('''
            SELECT DISTINCT er.entity_id, er.related_entity_id, er.relationship_type
            FROM entity_relationships er
            WHERE er.relationship_type IN ('CONTRACTOR_FOR', 'ENGINEERING_FOR', 'CONSULTANT_FOR')
        ''')
        return cur.fetchall()
    except Exception:
        return []


def build_contractor_relationships():
    """
    Main entry point: build/update contractor_developer_relationships.
    """
    print(f"[Relationship Mapper] START — {datetime.utcnow().isoformat()}")

    conn = get_db()
    cur = conn.cursor()

    pairs = _find_contractor_developer_pairs(cur)
    print(f"[Relationship Mapper] Found {len(pairs)} contractor-developer pairs from activity")

    relationships_updated = 0

    for firm_id, developer_name, co_occurrence in pairs:
        # Look up developer_id
        cur.execute('SELECT id FROM developers WHERE developer_name = ?', (developer_name,))
        dev_row = cur.fetchone()
        if not dev_row:
            continue
        developer_id = dev_row[0]

        # Calculate relationship strength (0-100)
        # Base: co_occurrence * 20, capped at 100
        strength = min(100, co_occurrence * 20)

        # Check if relationship exists
        cur.execute('''
            SELECT id, project_count FROM contractor_developer_relationships
            WHERE contractor_id = ? AND developer_id = ?
        ''', (firm_id, developer_id))
        existing = cur.fetchone()

        if existing:
            cur.execute('''
                UPDATE contractor_developer_relationships
                SET project_count = ?, relationship_strength = ?
                WHERE id = ?
            ''', (co_occurrence, strength, existing[0]))
        else:
            cur.execute('''
                INSERT INTO contractor_developer_relationships
                (id, contractor_id, developer_id, project_count, relationship_strength)
                VALUES (?, ?, ?, ?, ?)
            ''', (str(uuid.uuid4()), firm_id, developer_id, co_occurrence, strength))

        relationships_updated += 1

    # Also process entity_relationships
    er_pairs = _find_pairs_from_entity_relationships(cur)
    for entity_id, related_id, rel_type in er_pairs:
        # Try to match entity_id to a contractor firm
        cur.execute('SELECT id FROM contractor_firms WHERE id = ?', (entity_id,))
        if not cur.fetchone():
            continue
        cur.execute('SELECT id FROM developers WHERE id = ?', (related_id,))
        if not cur.fetchone():
            continue

        cur.execute('''
            SELECT id FROM contractor_developer_relationships
            WHERE contractor_id = ? AND developer_id = ?
        ''', (entity_id, related_id))
        if not cur.fetchone():
            cur.execute('''
                INSERT INTO contractor_developer_relationships
                (id, contractor_id, developer_id, project_count, relationship_strength)
                VALUES (?, ?, ?, ?, ?)
            ''', (str(uuid.uuid4()), entity_id, related_id, 1, 30))
            relationships_updated += 1

    conn.commit()
    conn.close()

    print(f"[Relationship Mapper] COMPLETE — {relationships_updated} relationships updated")
    return {'relationships_updated': relationships_updated}
