"""
Developer Entity Resolver.
Resolves LLC ownership to parent developers by detecting name similarity
patterns. Developers frequently create city-specific LLCs to purchase land.

Example:
  Crescent Phoenix Land LLC → Crescent Communities
  Crescent Dallas Residential LLC → Crescent Communities
"""
import re
import json
import uuid
from db import get_db


# Common LLC suffixes to strip for matching
_SUFFIXES = [
    ' LLC', ' Inc', ' Inc.', ' Corp', ' Corp.', ' Co.', ' LP', ' LLP',
    ' Ltd', ' Ltd.', ' Partners', ' Holdings', ' Trust', ' Group',
    ' Development', ' Developments', ' Properties', ' Realty', ' Homes',
]

# City/state words to strip for root-name extraction
_GEO_WORDS = set([
    'phoenix', 'dallas', 'atlanta', 'charlotte', 'nashville', 'tampa',
    'orlando', 'denver', 'raleigh', 'austin', 'houston', 'san antonio',
    'jacksonville', 'greenville', 'scottsdale', 'mesa', 'chandler',
    'gilbert', 'tempe', 'glendale', 'frisco', 'mckinney', 'plano',
    'fort worth', 'arlington', 'boise', 'las vegas', 'salt lake city',
    'tucson', 'columbia', 'charleston', 'savannah', 'huntsville',
    'birmingham', 'knoxville', 'spartanburg',
    'land', 'residential', 'commercial', 'industrial', 'north', 'south',
    'east', 'west', 'central', 'community', 'communities', 'property',
    'venture', 'ventures', 'capital', 'invest', 'investments',
])


def _strip_suffix(name):
    """Remove corporate suffixes."""
    clean = name.strip()
    for sfx in _SUFFIXES:
        if clean.endswith(sfx):
            clean = clean[:-len(sfx)].strip()
    return clean


def _extract_root_name(name):
    """Extract the probable developer root name by stripping geo/generic words."""
    clean = _strip_suffix(name)
    words = clean.split()
    root_words = [w for w in words if w.lower() not in _GEO_WORDS]
    if not root_words:
        return clean  # fallback: don't strip everything
    return ' '.join(root_words)


def _names_share_root(name_a, name_b, min_length=3):
    """Check if two entity names share a significant root name."""
    root_a = _extract_root_name(name_a).lower()
    root_b = _extract_root_name(name_b).lower()
    if len(root_a) < min_length or len(root_b) < min_length:
        return False
    # Exact root match
    if root_a == root_b:
        return True
    # One contains the other
    if root_a in root_b or root_b in root_a:
        return True
    return False


def resolve_developer_ownership():
    """
    Scan entity_relationships and development_events for LLC names,
    resolve them to parent developers, and create DEVELOPER_OWNS_LLC
    relationships.
    """
    conn = get_db()
    cur = conn.cursor()

    # Get all unique developer/company names from events
    cur.execute('''
        SELECT DISTINCT developer FROM development_events
        WHERE developer IS NOT NULL AND developer != ''
    ''')
    all_names = [r[0] for r in cur.fetchall()]

    if len(all_names) < 2:
        conn.close()
        print("[DevResolver] Not enough developer names to resolve.")
        return 0

    # Group by root name
    root_groups = {}
    for name in all_names:
        root = _extract_root_name(name).lower()
        root_groups.setdefault(root, []).append(name)

    created = 0

    for root, names in root_groups.items():
        if len(names) < 2:
            continue

        # The shortest name (without LLC suffix) is likely the parent
        parent = min(names, key=lambda n: len(_strip_suffix(n)))

        for name in names:
            if name == parent:
                continue
            # Only create relationship if they share a meaningful root
            if _names_share_root(parent, name):
                try:
                    cur.execute('''
                        SELECT id FROM entity_relationships
                        WHERE entity_a = ? AND entity_b = ? AND relationship_type = 'DEVELOPER_OWNS_LLC'
                        LIMIT 1
                    ''', (parent, name))
                    if not cur.fetchone():
                        cur.execute('''
                            INSERT INTO entity_relationships
                            (id, entity_a, entity_a_type, entity_b, entity_b_type,
                             relationship_type, source, confidence, created_at)
                            VALUES (?, ?, 'developer', ?, 'llc', 'DEVELOPER_OWNS_LLC',
                                    'entity_resolver', ?, CURRENT_TIMESTAMP)
                        ''', (str(uuid.uuid4()), parent, name, 70))
                        created += 1
                        print(f"[DevResolver] {parent} → owns → {name}")
                except Exception:
                    pass

    # Also try cross-referencing: if two different names appear in same city
    # within events and share a root, link them
    cur.execute('''
        SELECT developer, city, state FROM development_events
        WHERE developer IS NOT NULL AND developer != ''
        GROUP BY developer, city, state
    ''')
    dev_locations = cur.fetchall()

    location_devs = {}
    for dev, city, state in dev_locations:
        key = (city or '', state or '')
        location_devs.setdefault(key, []).append(dev)

    for loc, devs in location_devs.items():
        if len(devs) < 2:
            continue
        for i, dev_a in enumerate(devs):
            for dev_b in devs[i+1:]:
                if _names_share_root(dev_a, dev_b):
                    parent = min([dev_a, dev_b], key=lambda n: len(_strip_suffix(n)))
                    child = dev_b if parent == dev_a else dev_a
                    try:
                        cur.execute('''
                            SELECT id FROM entity_relationships
                            WHERE entity_a = ? AND entity_b = ? AND relationship_type = 'DEVELOPER_OWNS_LLC'
                            LIMIT 1
                        ''', (parent, child))
                        if not cur.fetchone():
                            cur.execute('''
                                INSERT INTO entity_relationships
                                (id, entity_a, entity_a_type, entity_b, entity_b_type,
                                 relationship_type, source, confidence, created_at)
                                VALUES (?, ?, 'developer', ?, 'llc', 'DEVELOPER_OWNS_LLC',
                                        'co_location_resolver', ?, CURRENT_TIMESTAMP)
                            ''', (str(uuid.uuid4()), parent, child, 60))
                            created += 1
                    except Exception:
                        pass

    conn.commit()
    conn.close()
    print(f"[DevResolver] Created {created} developer ownership relationships.")
    return created
