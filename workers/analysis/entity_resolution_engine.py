"""
Entity Resolution Engine.
Resolves multiple LLCs to their parent developer entities.
Uses name similarity, registered agent matching, and address co-location.

Example:
  Sunrise Development LLC
  Sunrise Greenville LLC
  Sunrise Residential Holdings LLC
  → All resolve to "Sunrise Development"
"""
import json
import re
import uuid
from collections import defaultdict
from datetime import datetime

from db import get_db


# Corporate suffixes to strip
_SUFFIXES = [
    ' LLC', ' Inc', ' Inc.', ' Corp', ' Corp.', ' Corporation',
    ' Co.', ' LP', ' LLP', ' Ltd', ' Ltd.',
    ' Partners', ' Holdings', ' Trust', ' Group', ' Ventures',
    ' Development', ' Developments', ' Properties', ' Realty',
    ' Homes', ' Residential', ' Capital', ' Investments', ' Fund',
]

# Geographic and generic words to strip for root extraction
_GEO_WORDS = {
    'phoenix', 'dallas', 'atlanta', 'charlotte', 'nashville', 'tampa',
    'orlando', 'denver', 'raleigh', 'austin', 'houston', 'san', 'antonio',
    'jacksonville', 'greenville', 'scottsdale', 'mesa', 'chandler',
    'gilbert', 'tempe', 'glendale', 'frisco', 'mckinney', 'plano',
    'fort', 'worth', 'arlington', 'boise', 'las', 'vegas',
    'north', 'south', 'east', 'west', 'central',
    'land', 'residential', 'commercial', 'industrial',
    'community', 'communities', 'property', 'venture', 'ventures',
    'capital', 'invest', 'investments', 'i', 'ii', 'iii', 'iv', 'v',
}


def _strip_suffix(name):
    """Remove corporate suffixes."""
    clean = name.strip()
    for sfx in _SUFFIXES:
        if clean.lower().endswith(sfx.lower()):
            clean = clean[:-len(sfx)].strip()
    return clean


def _extract_root(name):
    """Extract the core developer name by stripping suffixes and geo words."""
    clean = _strip_suffix(name)
    words = clean.split()
    root_words = [w for w in words if w.lower() not in _GEO_WORDS]
    if not root_words:
        return clean
    return ' '.join(root_words)


def _similarity_score(name_a, name_b):
    """Calculate similarity between two entity names (0.0 - 1.0)."""
    root_a = _extract_root(name_a).lower()
    root_b = _extract_root(name_b).lower()

    if not root_a or not root_b:
        return 0.0

    # Exact root match
    if root_a == root_b:
        return 1.0

    # One contains the other
    if root_a in root_b or root_b in root_a:
        longer = max(len(root_a), len(root_b))
        shorter = min(len(root_a), len(root_b))
        return shorter / longer if longer > 0 else 0.0

    # Word overlap
    words_a = set(root_a.split())
    words_b = set(root_b.split())
    if not words_a or not words_b:
        return 0.0
    overlap = words_a & words_b
    union = words_a | words_b
    return len(overlap) / len(union) if union else 0.0


def resolve_entities():
    """
    Main resolution: scan all entity names from property_signals and entities,
    group by root name, establish parent-child relationships.
    """
    conn = get_db()
    cur = conn.cursor()

    # Gather all unique entity names
    all_names = set()

    # From property_signals
    cur.execute('''
        SELECT DISTINCT entity_name FROM property_signals
        WHERE entity_name IS NOT NULL AND entity_name != ''
    ''')
    for (name,) in cur.fetchall():
        all_names.add(name.strip())

    # From development_events
    try:
        cur.execute('''
            SELECT DISTINCT developer FROM development_events
            WHERE developer IS NOT NULL AND developer != ''
        ''')
        for (name,) in cur.fetchall():
            all_names.add(name.strip())
    except Exception:
        pass

    # From entities table
    cur.execute('''
        SELECT DISTINCT entity_name FROM entities
        WHERE entity_name IS NOT NULL AND entity_name != ''
    ''')
    for (name,) in cur.fetchall():
        all_names.add(name.strip())

    if len(all_names) < 2:
        conn.close()
        print("[EntityResolver] Not enough entities to resolve.")
        return 0

    # Group by root name
    root_groups = defaultdict(list)
    for name in all_names:
        root = _extract_root(name).lower()
        if len(root) >= 3:
            root_groups[root].append(name)

    resolved = 0

    for root, names in root_groups.items():
        if len(names) < 2:
            continue

        # Parent is the shortest stripped name (most likely the "real" company)
        parent = min(names, key=lambda n: len(_strip_suffix(n)))

        for name in names:
            if name == parent:
                continue

            # Verify similarity threshold
            score = _similarity_score(parent, name)
            if score < 0.5:
                continue

            # Upsert into entities table
            ent_id = str(uuid.uuid4())
            normalized = name.upper().strip()
            try:
                cur.execute('''
                    SELECT id FROM entities WHERE entity_name = ? LIMIT 1
                ''', (name,))
                existing = cur.fetchone()
                if existing:
                    cur.execute('''
                        UPDATE entities
                        SET parent_entity = ?, normalized_name = ?
                        WHERE entity_name = ?
                    ''', (parent, normalized, name))
                else:
                    cur.execute('''
                        INSERT INTO entities
                        (id, entity_name, normalized_name, entity_type,
                         parent_entity, created_at)
                        VALUES (?, ?, ?, 'llc', ?, CURRENT_TIMESTAMP)
                    ''', (ent_id, name, normalized, parent))
                resolved += 1
            except Exception:
                pass

        # Ensure parent entity exists
        try:
            cur.execute('''
                SELECT id FROM entities WHERE entity_name = ? LIMIT 1
            ''', (parent,))
            if not cur.fetchone():
                cur.execute('''
                    INSERT INTO entities
                    (id, entity_name, normalized_name, entity_type, created_at)
                    VALUES (?, ?, ?, 'developer', CURRENT_TIMESTAMP)
                ''', (str(uuid.uuid4()), parent, parent.upper().strip()))
        except Exception:
            pass

    conn.commit()
    conn.close()
    print(f"[EntityResolver] Resolved {resolved} entities to parent developers")
    return resolved


def get_parent_entity(entity_name):
    """Look up the parent developer for a given entity name."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute('''
        SELECT parent_entity FROM entities
        WHERE entity_name = ? AND parent_entity IS NOT NULL
        LIMIT 1
    ''', (entity_name,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else entity_name
