"""
Developer Network Intelligence Engine.
Builds a relationship graph connecting developers, contractors, engineers,
architects, lenders, and suppliers based on co-occurrence in development signals.

Uses signals from:
  - contractor intelligence
  - supply chain intelligence
  - planning agenda signals
  - permit signals
  - entity filings
  - construction financing signals

When entities repeatedly appear together, relationship_strength increases.
When known entity clusters appear in new cities/projects, development
probability is boosted.
"""
import json
import uuid
from collections import defaultdict
from datetime import datetime, timedelta

from db import get_db


# ---------------------------------------------------------------------------
# Relationship type constants
# ---------------------------------------------------------------------------
REL_DEVELOPER_CONTRACTOR = 'DEVELOPER_CONTRACTOR'
REL_DEVELOPER_ENGINEER = 'DEVELOPER_ENGINEER'
REL_DEVELOPER_ARCHITECT = 'DEVELOPER_ARCHITECT'
REL_DEVELOPER_LENDER = 'DEVELOPER_LENDER'
REL_CONTRACTOR_SUPPLIER = 'CONTRACTOR_SUPPLIER'
REL_DEVELOPER_SUPPLIER = 'DEVELOPER_SUPPLIER'
REL_CONTRACTOR_ENGINEER = 'CONTRACTOR_ENGINEER'
REL_LENDER_DEVELOPER = 'LENDER_DEVELOPER'

ALL_RELATIONSHIP_TYPES = {
    REL_DEVELOPER_CONTRACTOR,
    REL_DEVELOPER_ENGINEER,
    REL_DEVELOPER_ARCHITECT,
    REL_DEVELOPER_LENDER,
    REL_CONTRACTOR_SUPPLIER,
    REL_DEVELOPER_SUPPLIER,
    REL_CONTRACTOR_ENGINEER,
    REL_LENDER_DEVELOPER,
}

# Signal types that carry entity pair information
SIGNAL_SOURCES = {
    'contractor': [
        'CONTRACTOR_BID', 'SITE_PLAN_PREP', 'ENGINEERING_PLAN_SUBMISSION',
        'SITE_GRADING', 'SURVEY_WORK',
    ],
    'supply_chain': [
        'CIVIL_ENGINEERING_PLAN', 'SITE_PREP_ACTIVITY',
        'UTILITY_CONNECTION_REQUEST', 'EARTHWORK_CONTRACTOR',
        'CONCRETE_SUPPLY_SIGNAL', 'INFRASTRUCTURE_BID',
    ],
    'planning': [
        'ZONING_AGENDA_ITEM', 'SITE_PLAN_SUBMISSION',
        'SUBDIVISION_APPLICATION', 'REZONING_REQUEST',
        'DEVELOPMENT_REVIEW_CASE',
    ],
    'permit': [
        'BUILDING_PERMIT', 'MULTIFAMILY_PERMIT',
        'SUBDIVISION_PERMIT', 'SITE_DEVELOPMENT_PERMIT',
        'RESIDENTIAL_COMPLEX_PERMIT',
    ],
    'financing': [
        'CONSTRUCTION_FINANCING', 'COMMERCIAL_MORTGAGE', 'SECURED_LOAN',
    ],
    'land': [
        'LAND_PURCHASE', 'DEED_TRANSFER', 'OWNER_CHANGE',
    ],
}


# ---------------------------------------------------------------------------
# Entity extraction helpers
# ---------------------------------------------------------------------------

def _extract_entities_from_signal(signal):
    """Extract entity names and roles from a property signal row."""
    entities = []

    entity_name = (signal.get('entity_name') or '').strip()
    if entity_name:
        entities.append(('developer', entity_name))

    metadata = signal.get('metadata')
    if metadata:
        try:
            meta = json.loads(metadata) if isinstance(metadata, str) else metadata
        except (json.JSONDecodeError, TypeError):
            meta = {}

        for key, role in [
            ('contractor', 'contractor'),
            ('engineer', 'engineer'),
            ('architect', 'architect'),
            ('lender', 'lender'),
            ('supplier', 'supplier'),
            ('firm', 'contractor'),
            ('consultant', 'engineer'),
            ('company', 'contractor'),
            ('applicant', 'developer'),
            ('owner', 'developer'),
            ('builder', 'contractor'),
            ('civil_engineer', 'engineer'),
            ('financing_entity', 'lender'),
            ('bank', 'lender'),
        ]:
            val = (meta.get(key) or '').strip()
            if val and val != entity_name:
                entities.append((role, val))

    return entities


def _determine_relationship_type(role_a, role_b):
    """Determine the relationship type between two entity roles."""
    pair = frozenset([role_a, role_b])

    mapping = {
        frozenset(['developer', 'contractor']): REL_DEVELOPER_CONTRACTOR,
        frozenset(['developer', 'engineer']): REL_DEVELOPER_ENGINEER,
        frozenset(['developer', 'architect']): REL_DEVELOPER_ARCHITECT,
        frozenset(['developer', 'lender']): REL_DEVELOPER_LENDER,
        frozenset(['developer', 'supplier']): REL_DEVELOPER_SUPPLIER,
        frozenset(['contractor', 'supplier']): REL_CONTRACTOR_SUPPLIER,
        frozenset(['contractor', 'engineer']): REL_CONTRACTOR_ENGINEER,
        frozenset(['lender', 'developer']): REL_LENDER_DEVELOPER,
    }

    return mapping.get(pair, f'{role_a.upper()}_{role_b.upper()}')


# ---------------------------------------------------------------------------
# Core network graph builder
# ---------------------------------------------------------------------------

def _collect_entity_pairs():
    """
    Scan property_signals and related tables to extract entity co-occurrences.
    Returns list of (entity_a, entity_b, relationship_type, signal_date) tuples.
    """
    conn = get_db()
    cur = conn.cursor()
    pairs = []

    # 1. Property signals — extract entity pairs from metadata
    cur.execute('''
        SELECT entity_name, signal_type, metadata, city, state, created_at
        FROM property_signals
        WHERE entity_name IS NOT NULL AND entity_name != ''
        ORDER BY created_at DESC
    ''')
    rows = cur.fetchall()

    for row in rows:
        signal = {
            'entity_name': row[0],
            'signal_type': row[1],
            'metadata': row[2],
            'city': row[3],
            'state': row[4],
            'created_at': row[5],
        }
        entities = _extract_entities_from_signal(signal)

        # Create pairs from all entities found in the same signal
        for i in range(len(entities)):
            for j in range(i + 1, len(entities)):
                role_a, name_a = entities[i]
                role_b, name_b = entities[j]
                if name_a.lower() == name_b.lower():
                    continue
                rel_type = _determine_relationship_type(role_a, role_b)
                pairs.append((name_a, name_b, rel_type, signal.get('created_at')))

    # 2. Contractor-developer relationships from existing table
    cur.execute('''
        SELECT cf.firm_name, cdr.developer_id, cdr.project_count
        FROM contractor_developer_relationships cdr
        JOIN contractor_firms cf ON cf.id = cdr.contractor_id
        WHERE cf.firm_name IS NOT NULL
    ''')
    for row in cur.fetchall():
        firm_name, dev_id, count = row[0], row[1], row[2] or 1
        if firm_name and dev_id:
            for _ in range(min(count, 10)):
                pairs.append((dev_id, firm_name, REL_DEVELOPER_CONTRACTOR, None))

    # 3. Entity relationships from existing table
    cur.execute('''
        SELECT entity_a, entity_b, relationship_type
        FROM entity_relationships
        WHERE entity_a IS NOT NULL AND entity_b IS NOT NULL
    ''')
    for row in cur.fetchall():
        pairs.append((row[0], row[1], row[2] or REL_DEVELOPER_CONTRACTOR, None))

    # 4. Construction financing signals — developer + lender pairs
    cur.execute('''
        SELECT entity_name, metadata, created_at
        FROM property_signals
        WHERE signal_type IN ('CONSTRUCTION_FINANCING', 'COMMERCIAL_MORTGAGE', 'SECURED_LOAN')
        AND entity_name IS NOT NULL AND entity_name != ''
    ''')
    for row in cur.fetchall():
        entity = row[0]
        meta_str = row[1]
        sig_date = row[2]
        if meta_str:
            try:
                meta = json.loads(meta_str) if isinstance(meta_str, str) else meta_str
                lender = (meta.get('lender') or meta.get('bank') or
                          meta.get('financing_entity') or '').strip()
                if lender and lender.lower() != entity.lower():
                    pairs.append((entity, lender, REL_DEVELOPER_LENDER, sig_date))
            except (json.JSONDecodeError, TypeError):
                pass

    conn.close()
    return pairs


def _aggregate_network_edges(pairs):
    """
    Aggregate entity pairs into network edges with co-occurrence counts
    and relationship strength.
    """
    edges = defaultdict(lambda: {
        'co_occurrence_count': 0,
        'relationship_type': None,
        'last_seen': None,
    })

    for entity_a, entity_b, rel_type, sig_date in pairs:
        # Normalize edge key — always alphabetical order for consistency
        if entity_a.lower() > entity_b.lower():
            entity_a, entity_b = entity_b, entity_a

        key = (entity_a, entity_b)
        edge = edges[key]
        edge['co_occurrence_count'] += 1
        edge['relationship_type'] = rel_type

        if sig_date:
            ts = str(sig_date)
            if edge['last_seen'] is None or ts > edge['last_seen']:
                edge['last_seen'] = ts

    return edges


def _calculate_relationship_strength(co_occurrence_count, last_seen):
    """
    Calculate relationship strength (0-100) based on co-occurrence count
    and recency.
    """
    # Base strength from co-occurrences (logarithmic scaling)
    if co_occurrence_count >= 10:
        base = 80
    elif co_occurrence_count >= 5:
        base = 60
    elif co_occurrence_count >= 3:
        base = 40
    elif co_occurrence_count >= 2:
        base = 25
    else:
        base = 10

    # Recency bonus
    recency_bonus = 0
    if last_seen:
        try:
            last_dt = datetime.fromisoformat(str(last_seen).replace('Z', '+00:00'))
            days_ago = (datetime.utcnow() - last_dt.replace(tzinfo=None)).days
            if days_ago <= 30:
                recency_bonus = 20
            elif days_ago <= 90:
                recency_bonus = 15
            elif days_ago <= 180:
                recency_bonus = 10
            elif days_ago <= 365:
                recency_bonus = 5
        except (ValueError, TypeError):
            pass

    return min(100, base + recency_bonus)


# ---------------------------------------------------------------------------
# Store edges to database
# ---------------------------------------------------------------------------

def _store_network_edges(edges):
    """Write aggregated edges to developer_network_edges table."""
    conn = get_db()
    cur = conn.cursor()

    stored = 0
    for (entity_a, entity_b), edge_data in edges.items():
        co_count = edge_data['co_occurrence_count']
        rel_type = edge_data['relationship_type']
        last_seen = edge_data['last_seen'] or datetime.utcnow().isoformat()
        strength = _calculate_relationship_strength(co_count, last_seen)

        # Upsert edge
        cur.execute('''
            SELECT id, co_occurrence_count FROM developer_network_edges
            WHERE entity_a = ? AND entity_b = ?
        ''', (entity_a, entity_b))
        existing = cur.fetchone()

        if existing:
            new_count = max(existing[1] or 0, co_count)
            new_strength = _calculate_relationship_strength(new_count, last_seen)
            cur.execute('''
                UPDATE developer_network_edges
                SET co_occurrence_count = ?,
                    relationship_strength = ?,
                    last_seen = ?,
                    relationship_type = ?
                WHERE id = ?
            ''', (new_count, new_strength, last_seen, rel_type, existing[0]))
        else:
            cur.execute('''
                INSERT INTO developer_network_edges
                    (id, entity_a, entity_b, relationship_type,
                     co_occurrence_count, last_seen, relationship_strength)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (str(uuid.uuid4()), entity_a, entity_b, rel_type,
                  co_count, last_seen, strength))
        stored += 1

    conn.commit()
    conn.close()
    return stored


# ---------------------------------------------------------------------------
# Network-based probability boost
# ---------------------------------------------------------------------------

def _boost_probability_from_networks():
    """
    When known developer-contractor-engineer clusters appear together
    in new projects, boost the development probability for those parcels.
    """
    conn = get_db()
    cur = conn.cursor()

    # Find strong network clusters (strength >= 50)
    cur.execute('''
        SELECT entity_a, entity_b, relationship_strength
        FROM developer_network_edges
        WHERE relationship_strength >= 50
    ''')
    strong_edges = cur.fetchall()

    # Build adjacency map of strong relationships
    network = defaultdict(set)
    for entity_a, entity_b, strength in strong_edges:
        network[entity_a].add(entity_b)
        network[entity_b].add(entity_a)

    # Find parcels where multiple network members appear
    boosted = 0
    for hub_entity, connected in network.items():
        if len(connected) < 2:
            continue

        # Check if hub entity has recent signals
        cur.execute('''
            SELECT DISTINCT parcel_id, city, state
            FROM property_signals
            WHERE entity_name = ?
            AND parcel_id IS NOT NULL
            AND created_at >= ?
        ''', (hub_entity, (datetime.utcnow() - timedelta(days=180)).isoformat()))
        parcels = cur.fetchall()

        for parcel_row in parcels:
            parcel_id = parcel_row[0]
            if not parcel_id:
                continue

            # Count how many connected entities also have signals for this parcel
            connected_present = 0
            for partner in connected:
                cur.execute('''
                    SELECT COUNT(*) FROM property_signals
                    WHERE entity_name = ? AND parcel_id = ?
                ''', (partner, parcel_id))
                cnt = cur.fetchone()[0]
                if cnt > 0:
                    connected_present += 1

            if connected_present >= 1:
                # Boost development probability
                boost = min(15, connected_present * 5)
                cur.execute('''
                    UPDATE parcels
                    SET development_probability = MIN(99,
                        COALESCE(development_probability, 0) + ?)
                    WHERE parcel_id = ?
                ''', (boost, parcel_id))
                boosted += 1

    conn.commit()
    conn.close()
    return boosted


# ---------------------------------------------------------------------------
# Query helpers for dashboard integration
# ---------------------------------------------------------------------------

def get_developer_network(developer_name, min_strength=10):
    """Get all network connections for a specific developer."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute('''
        SELECT entity_a, entity_b, relationship_type,
               co_occurrence_count, relationship_strength, last_seen
        FROM developer_network_edges
        WHERE (entity_a = ? OR entity_b = ?)
        AND relationship_strength >= ?
        ORDER BY relationship_strength DESC
    ''', (developer_name, developer_name, min_strength))
    rows = cur.fetchall()
    conn.close()

    edges = []
    for row in rows:
        partner = row[1] if row[0] == developer_name else row[0]
        edges.append({
            'partner': partner,
            'relationship_type': row[2],
            'co_occurrence_count': row[3],
            'relationship_strength': row[4],
            'last_seen': row[5],
        })
    return edges


def get_top_network_clusters(limit=20):
    """Get the strongest network clusters for the dashboard."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute('''
        SELECT entity_a, entity_b, relationship_type,
               co_occurrence_count, relationship_strength, last_seen
        FROM developer_network_edges
        ORDER BY relationship_strength DESC, co_occurrence_count DESC
        LIMIT ?
    ''', (limit,))
    rows = cur.fetchall()
    conn.close()

    return [{
        'entity_a': r[0],
        'entity_b': r[1],
        'relationship_type': r[2],
        'co_occurrence_count': r[3],
        'relationship_strength': r[4],
        'last_seen': r[5],
    } for r in rows]


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_developer_network_graph():
    """
    Main entry point — build the developer network graph from all
    available signal sources.
    """
    print("[DeveloperNetworkGraph] Starting network graph build...")

    # Step 1: Collect entity pairs from all signal sources
    pairs = _collect_entity_pairs()
    print(f"[DeveloperNetworkGraph] Extracted {len(pairs)} entity co-occurrence pairs")

    if not pairs:
        print("[DeveloperNetworkGraph] No entity pairs found — skipping")
        return {'edges_stored': 0, 'probability_boosts': 0}

    # Step 2: Aggregate into network edges
    edges = _aggregate_network_edges(pairs)
    print(f"[DeveloperNetworkGraph] Aggregated into {len(edges)} unique edges")

    # Step 3: Store edges
    stored = _store_network_edges(edges)
    print(f"[DeveloperNetworkGraph] Stored {stored} network edges")

    # Step 4: Boost development probability based on network patterns
    boosted = _boost_probability_from_networks()
    print(f"[DeveloperNetworkGraph] Boosted probability for {boosted} parcels")

    print("[DeveloperNetworkGraph] Network graph build complete")
    return {'edges_stored': stored, 'probability_boosts': boosted}


if __name__ == '__main__':
    run_developer_network_graph()
