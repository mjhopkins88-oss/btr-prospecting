"""
Signal Graph Intelligence Engine.
Builds and analyzes an entity relationship network across the development ecosystem.
Identifies frequently occurring development partnerships and detects when
known partners appear in new signals — inferring developer involvement
even when the developer is not directly visible.

Entity types: developer, contractor, engineer, architect, supplier, parcel, city
Relationship types: developer→engineer, engineer→contractor, contractor→parcel, etc.
"""
import json
import uuid
from collections import defaultdict
from datetime import datetime, timedelta

from db import get_db


# Relationship types for the graph
REL_DEVELOPER_ENGINEER = 'DEVELOPER_USES_ENGINEER'
REL_DEVELOPER_CONTRACTOR = 'DEVELOPER_USES_CONTRACTOR'
REL_DEVELOPER_ARCHITECT = 'DEVELOPER_USES_ARCHITECT'
REL_DEVELOPER_SUPPLIER = 'DEVELOPER_USES_SUPPLIER'
REL_ENGINEER_CONTRACTOR = 'ENGINEER_WORKS_WITH_CONTRACTOR'
REL_CONTRACTOR_PARCEL = 'CONTRACTOR_ACTIVE_ON_PARCEL'
REL_ENGINEER_PARCEL = 'ENGINEER_ACTIVE_ON_PARCEL'
REL_DEVELOPER_PARCEL = 'DEVELOPER_LINKED_TO_PARCEL'
REL_SUPPLIER_PARCEL = 'SUPPLIER_ACTIVE_ON_PARCEL'

# Partnership detection thresholds
MIN_CO_OCCURRENCES = 2       # Minimum times two entities appear together
PARTNERSHIP_CONFIDENCE = 70  # Base confidence for detected partnerships
INFERENCE_CONFIDENCE = 60    # Base confidence for inferred developer involvement


def build_graph_from_signals():
    """
    Build entity relationship graph from property_signals and development_events.
    Extracts entity pairs and creates/updates relationships with strength scoring.
    """
    conn = get_db()
    cur = conn.cursor()

    cutoff = (datetime.utcnow() - timedelta(days=365)).isoformat()
    created = 0

    # 1. Build relationships from property_signals (entity→parcel, entity→city)
    cur.execute('''
        SELECT entity_name, parcel_id, city, state, signal_type, source, metadata
        FROM property_signals
        WHERE created_at >= ? AND entity_name IS NOT NULL AND entity_name != ''
    ''', (cutoff,))
    rows = cur.fetchall()
    cols = [d[0] for d in cur.description]

    for row in rows:
        sig = dict(zip(cols, row))
        entity = sig['entity_name']
        parcel = sig['parcel_id']
        signal_type = sig['signal_type'] or ''

        # Determine entity type from signal
        entity_type = _infer_entity_type(entity, signal_type)

        # Entity → parcel relationship
        if parcel:
            rel_type = {
                'engineer': REL_ENGINEER_PARCEL,
                'contractor': REL_CONTRACTOR_PARCEL,
                'supplier': REL_SUPPLIER_PARCEL,
                'developer': REL_DEVELOPER_PARCEL,
            }.get(entity_type, REL_DEVELOPER_PARCEL)

            if _upsert_relationship(cur, entity, entity_type, parcel, 'parcel',
                                     rel_type, 'signal_graph', 60):
                created += 1

        # Parse metadata for additional entities
        meta = {}
        if sig.get('metadata'):
            try:
                meta = json.loads(sig['metadata']) if isinstance(sig['metadata'], str) else sig['metadata']
            except Exception:
                pass

        # If metadata contains developer + engineer/contractor, link them
        dev_name = meta.get('developer') or meta.get('raw', {}).get('developer')
        eng_firm = meta.get('engineering_firm') or meta.get('raw', {}).get('engineering_firm')

        if dev_name and eng_firm and dev_name != eng_firm:
            if _upsert_relationship(cur, dev_name, 'developer', eng_firm, 'engineer',
                                     REL_DEVELOPER_ENGINEER, 'signal_graph', 65):
                created += 1

    # 2. Build engineer↔contractor links from co-location on same parcel
    created += _build_co_location_links(cur, cutoff)

    conn.commit()
    conn.close()
    print(f"[SignalGraph] Built {created} new relationships")
    return created


def _infer_entity_type(entity_name, signal_type):
    """Infer entity type from name and signal context."""
    lower = (entity_name or '').lower()
    st_upper = (signal_type or '').upper()

    if st_upper in ('ENGINEERING_ENGAGEMENT', 'CIVIL_ENGINEERING_PLAN'):
        return 'engineer'
    if st_upper in ('CONTRACTOR_ACTIVITY', 'EARTHWORK_CONTRACTOR', 'INFRASTRUCTURE_BID',
                     'SITE_PREP_ACTIVITY'):
        return 'contractor'
    if st_upper in ('CONCRETE_SUPPLY_SIGNAL',):
        return 'supplier'

    eng_keywords = ['engineering', 'engineers', 'design', 'survey', 'surveying',
                    'planning', 'consulting', 'consultants']
    if any(kw in lower for kw in eng_keywords):
        return 'engineer'

    contractor_keywords = ['construction', 'builders', 'contracting', 'grading',
                           'excavation', 'earthwork', 'paving', 'concrete']
    if any(kw in lower for kw in contractor_keywords):
        return 'contractor'

    supplier_keywords = ['supply', 'materials', 'concrete', 'lumber', 'steel']
    if any(kw in lower for kw in supplier_keywords):
        return 'supplier'

    architect_keywords = ['architect', 'architecture']
    if any(kw in lower for kw in architect_keywords):
        return 'architect'

    return 'developer'


def _upsert_relationship(cur, entity_a, type_a, entity_b, type_b,
                          rel_type, source, confidence):
    """Insert or strengthen a relationship. Returns True if new."""
    try:
        cur.execute('''
            SELECT id, confidence, relationship_strength FROM entity_relationships
            WHERE entity_a = ? AND entity_b = ? AND relationship_type = ?
            LIMIT 1
        ''', (entity_a, entity_b, rel_type))
        existing = cur.fetchone()

        if existing:
            # Strengthen existing relationship
            old_strength = existing[2] or 0
            new_strength = min(old_strength + 10, 100)
            new_confidence = min(max(existing[1] or 0, confidence), 100)
            cur.execute('''
                UPDATE entity_relationships
                SET relationship_strength = ?, confidence = ?
                WHERE id = ?
            ''', (new_strength, new_confidence, existing[0]))
            return False
        else:
            cur.execute('''
                INSERT INTO entity_relationships
                (id, entity_a, entity_a_type, entity_b, entity_b_type,
                 relationship_type, source, confidence, relationship_strength,
                 created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                str(uuid.uuid4()), entity_a, type_a, entity_b, type_b,
                rel_type, source, confidence, 10,
            ))
            return True
    except Exception:
        return False


def _build_co_location_links(cur, cutoff):
    """Build links between entities that appear on the same parcel."""
    cur.execute('''
        SELECT parcel_id, entity_name, signal_type
        FROM property_signals
        WHERE parcel_id IS NOT NULL AND parcel_id != ''
        AND entity_name IS NOT NULL AND entity_name != ''
        AND created_at >= ?
    ''', (cutoff,))
    rows = cur.fetchall()

    # Group entities by parcel
    parcel_entities = defaultdict(list)
    for parcel_id, entity, signal_type in rows:
        etype = _infer_entity_type(entity, signal_type)
        parcel_entities[parcel_id].append((entity, etype))

    created = 0
    for parcel_id, entities in parcel_entities.items():
        if len(entities) < 2:
            continue
        # Link each pair
        for i, (name_a, type_a) in enumerate(entities):
            for name_b, type_b in entities[i+1:]:
                if name_a == name_b:
                    continue
                rel_type = _pair_relationship_type(type_a, type_b)
                if rel_type and _upsert_relationship(
                    cur, name_a, type_a, name_b, type_b,
                    rel_type, 'co_location', 55
                ):
                    created += 1
    return created


def _pair_relationship_type(type_a, type_b):
    """Determine relationship type for an entity pair."""
    pair = frozenset([type_a, type_b])
    mapping = {
        frozenset(['developer', 'engineer']): REL_DEVELOPER_ENGINEER,
        frozenset(['developer', 'contractor']): REL_DEVELOPER_CONTRACTOR,
        frozenset(['developer', 'architect']): REL_DEVELOPER_ARCHITECT,
        frozenset(['developer', 'supplier']): REL_DEVELOPER_SUPPLIER,
        frozenset(['engineer', 'contractor']): REL_ENGINEER_CONTRACTOR,
    }
    return mapping.get(pair)


def detect_partnerships():
    """
    Identify frequently occurring development partnerships.
    A partnership is when two entities appear together on multiple parcels or projects.
    """
    conn = get_db()
    cur = conn.cursor()

    # Find entity pairs that co-occur on multiple parcels
    cur.execute('''
        SELECT entity_a, entity_a_type, entity_b, entity_b_type,
               relationship_type, COUNT(*) as co_occurrences,
               AVG(confidence) as avg_confidence
        FROM entity_relationships
        WHERE relationship_type IN (?, ?, ?, ?, ?)
        GROUP BY entity_a, entity_b, relationship_type
        HAVING co_occurrences >= 1
        ORDER BY co_occurrences DESC
    ''', (
        REL_DEVELOPER_ENGINEER, REL_DEVELOPER_CONTRACTOR,
        REL_DEVELOPER_ARCHITECT, REL_ENGINEER_CONTRACTOR,
        REL_DEVELOPER_SUPPLIER,
    ))
    partnerships = cur.fetchall()

    # Strengthen relationships for multi-occurrence pairs
    strengthened = 0
    for entity_a, type_a, entity_b, type_b, rel_type, count, avg_conf in partnerships:
        if count >= MIN_CO_OCCURRENCES:
            strength = min(count * 15, 100)
            confidence = min(int(avg_conf) + (count * 5), 100)
            try:
                cur.execute('''
                    UPDATE entity_relationships
                    SET relationship_strength = MAX(COALESCE(relationship_strength, 0), ?),
                        confidence = MAX(COALESCE(confidence, 0), ?)
                    WHERE entity_a = ? AND entity_b = ? AND relationship_type = ?
                ''', (strength, confidence, entity_a, entity_b, rel_type))
                strengthened += 1
            except Exception:
                pass

    conn.commit()
    conn.close()
    print(f"[SignalGraph] Strengthened {strengthened} partnerships")
    return strengthened


def infer_developer_from_partners(parcel_id):
    """
    Given a parcel, check if known engineer/contractor partners suggest
    a specific developer's involvement (even if developer not directly visible).

    Returns list of (developer, confidence) tuples.
    """
    conn = get_db()
    cur = conn.cursor()

    # Get entities active on this parcel
    cur.execute('''
        SELECT entity_name, signal_type FROM property_signals
        WHERE parcel_id = ? AND entity_name IS NOT NULL AND entity_name != ''
    ''', (parcel_id,))
    parcel_entities = []
    for name, st in cur.fetchall():
        parcel_entities.append((name, _infer_entity_type(name, st)))

    if not parcel_entities:
        conn.close()
        return []

    # For each non-developer entity, find developers they've worked with
    developer_votes = defaultdict(lambda: {'count': 0, 'total_strength': 0})

    for entity_name, entity_type in parcel_entities:
        if entity_type == 'developer':
            continue
        # Find developers linked to this entity
        cur.execute('''
            SELECT entity_a, relationship_strength, confidence
            FROM entity_relationships
            WHERE entity_b = ? AND entity_a_type = 'developer'
            AND relationship_strength >= 20
        ''', (entity_name,))
        for dev, strength, conf in cur.fetchall():
            developer_votes[dev]['count'] += 1
            developer_votes[dev]['total_strength'] += (strength or 0)

        cur.execute('''
            SELECT entity_b, relationship_strength, confidence
            FROM entity_relationships
            WHERE entity_a = ? AND entity_b_type = 'developer'
            AND relationship_strength >= 20
        ''', (entity_name,))
        for dev, strength, conf in cur.fetchall():
            developer_votes[dev]['count'] += 1
            developer_votes[dev]['total_strength'] += (strength or 0)

    conn.close()

    # Score developers by number of partner matches and relationship strength
    results = []
    for dev, data in developer_votes.items():
        if data['count'] >= 1:
            confidence = min(
                INFERENCE_CONFIDENCE + (data['count'] * 10) + (data['total_strength'] // 10),
                95
            )
            results.append((dev, confidence))

    results.sort(key=lambda x: x[1], reverse=True)
    return results[:5]


def score_graph_relationships(parcel_id):
    """
    Calculate a relationship graph score (0-20) for a parcel.
    Based on number and strength of entity connections.
    """
    conn = get_db()
    cur = conn.cursor()

    cur.execute('''
        SELECT COUNT(*) as rel_count,
               COALESCE(AVG(relationship_strength), 0) as avg_strength,
               COALESCE(MAX(relationship_strength), 0) as max_strength
        FROM entity_relationships
        WHERE (entity_a = ? OR entity_b = ?)
        AND relationship_strength > 0
    ''', (parcel_id, parcel_id))
    row = cur.fetchone()
    conn.close()

    if not row or row[0] == 0:
        return 0

    rel_count, avg_strength, max_strength = row
    # Score: connections * avg_strength factor, capped at 20
    score = min(int(rel_count * 3 + avg_strength * 0.1), 20)
    return score


def run_signal_graph_engine():
    """Full signal graph intelligence cycle."""
    print(f"[SignalGraph] START — {datetime.utcnow().isoformat()}")

    # Phase 1: Build graph from signals
    new_rels = build_graph_from_signals()

    # Phase 2: Detect and strengthen partnerships
    partnerships = detect_partnerships()

    # Phase 3: Infer developer involvement on high-probability parcels
    inferences = _run_developer_inference()

    print(f"[SignalGraph] COMPLETE — {new_rels} new relationships, "
          f"{partnerships} partnerships strengthened, {inferences} developer inferences")
    return {
        'new_relationships': new_rels,
        'partnerships_strengthened': partnerships,
        'developer_inferences': inferences,
    }


def _run_developer_inference():
    """Run developer inference on parcels with signals but no direct developer."""
    conn = get_db()
    cur = conn.cursor()

    # Find parcels with signals but no developer entity
    cur.execute('''
        SELECT DISTINCT ps.parcel_id, ps.city, ps.state
        FROM property_signals ps
        WHERE ps.parcel_id IS NOT NULL AND ps.parcel_id != ''
        AND NOT EXISTS (
            SELECT 1 FROM property_signals ps2
            WHERE ps2.parcel_id = ps.parcel_id
            AND ps2.signal_type IN ('LAND_PURCHASE', 'DEVELOPER_EXPANSION')
        )
    ''')
    parcels = cur.fetchall()
    conn.close()

    inferred = 0
    for parcel_id, city, state in parcels:
        results = infer_developer_from_partners(parcel_id)
        if results:
            dev, confidence = results[0]
            if confidence >= 65:
                inferred += 1
                # Emit intelligence event
                try:
                    from app import log_intelligence_event
                    log_intelligence_event(
                        event_type='GRAPH_INFERENCE',
                        title=f"Developer inferred via graph — {city or 'Unknown'}, {state or ''}",
                        description=(
                            f"Graph analysis suggests {dev} involvement "
                            f"(confidence: {confidence}%) based on partner activity"
                        ),
                        city=city,
                        state=state,
                        related_entity=dev,
                        entity_id=parcel_id,
                    )
                except Exception:
                    pass

    return inferred
