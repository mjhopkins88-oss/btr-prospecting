"""
Entity Relationship Builder.
Scans development_events and extracts relationships between entities
(developers, LLCs, parcels, contractors, consultants).
Stores results in the entity_relationships table.
"""
import json
import re
import uuid
from datetime import datetime

from db import get_db


# Relationship type constants
REL_DEVELOPER_OWNS_LLC = 'DEVELOPER_OWNS_LLC'
REL_LLC_PURCHASED_PARCEL = 'LLC_PURCHASED_PARCEL'
REL_PARCEL_HAS_PERMIT = 'PARCEL_HAS_PERMIT'
REL_CONTRACTOR_BIDDING_PROJECT = 'CONTRACTOR_BIDDING_PROJECT'
REL_CONSULTANT_WORKING_PROJECT = 'CONSULTANT_WORKING_PROJECT'
REL_DEVELOPER_ASSOCIATED_PROJECT = 'DEVELOPER_ASSOCIATED_PROJECT'
REL_PARCEL_SOLD_BY = 'PARCEL_SOLD_BY'
REL_DEVELOPER_ACTIVE_IN_CITY = 'DEVELOPER_ACTIVE_IN_CITY'

# Patterns for extracting contractor/consultant names
_CONTRACTOR_PATTERNS = [
    re.compile(r'(?:general\s+contractor|gc|builder)[:\s]+([A-Z][A-Za-z\s&]+(?:LLC|Inc|Corp|Co\.?)?)', re.IGNORECASE),
    re.compile(r'([A-Z][A-Za-z\s&]+(?:Construction|Builders|Building|Contracting)(?:\s+(?:LLC|Inc|Corp|Co\.?))?)', re.IGNORECASE),
]

_CONSULTANT_PATTERNS = [
    re.compile(r'([A-Z][A-Za-z\s&]+(?:Engineering|Engineers|Architects|Architecture|Consulting|Consultants|Design|Planning)(?:\s+(?:LLC|Inc|Corp|Co\.?))?)', re.IGNORECASE),
]

_SELLER_PATTERNS = [
    re.compile(r'(?:seller|sold\s+by|conveyed\s+by|from)[:\s]+([A-Z][A-Za-z\s&]+(?:LLC|Inc|Corp|Co\.?|Holdings|Trust|Partners)?)', re.IGNORECASE),
]

_BUYER_PATTERNS = [
    re.compile(r'(?:buyer|purchased\s+by|acquired\s+by|to)[:\s]+([A-Z][A-Za-z\s&]+(?:LLC|Inc|Corp|Co\.?|Holdings|Trust|Partners)?)', re.IGNORECASE),
]


def _extract_entities_from_event(event):
    """Extract entity names from a development event's text and metadata."""
    entities = {
        'developers': set(),
        'parcels': set(),
        'contractors': set(),
        'consultants': set(),
        'sellers': set(),
        'buyers': set(),
    }

    text = ''
    if event.get('developer'):
        entities['developers'].add(event['developer'].strip())

    if event.get('parcel_id'):
        entities['parcels'].add(event['parcel_id'].strip())

    # Parse metadata
    meta = {}
    if event.get('metadata'):
        try:
            meta = json.loads(event['metadata']) if isinstance(event['metadata'], str) else event['metadata']
        except Exception:
            pass

    headline = meta.get('headline', '')
    signal_text = meta.get('signal_text', '')
    text = f"{headline} {signal_text} {event.get('developer', '')}"

    # Extract contractors
    for pat in _CONTRACTOR_PATTERNS:
        for match in pat.finditer(text):
            name = match.group(1).strip()
            if len(name) > 3 and len(name) < 80:
                entities['contractors'].add(name)

    # Extract consultants
    for pat in _CONSULTANT_PATTERNS:
        for match in pat.finditer(text):
            name = match.group(1).strip()
            if len(name) > 3 and len(name) < 80:
                entities['consultants'].add(name)

    # Extract sellers
    for pat in _SELLER_PATTERNS:
        for match in pat.finditer(text):
            name = match.group(1).strip()
            if len(name) > 3 and len(name) < 80:
                entities['sellers'].add(name)

    # Extract buyers
    for pat in _BUYER_PATTERNS:
        for match in pat.finditer(text):
            name = match.group(1).strip()
            if len(name) > 3 and len(name) < 80:
                entities['buyers'].add(name)

    return entities


def _store_relationship(cur, entity_a, entity_a_type, entity_b, entity_b_type,
                        rel_type, source=None, confidence=50, metadata=None):
    """Insert a relationship, skipping if it already exists."""
    try:
        cur.execute('''
            SELECT id FROM entity_relationships
            WHERE entity_a = ? AND entity_b = ? AND relationship_type = ?
            LIMIT 1
        ''', (entity_a, entity_b, rel_type))
        if cur.fetchone():
            return False  # already exists

        cur.execute('''
            INSERT INTO entity_relationships
            (id, entity_a, entity_a_type, entity_b, entity_b_type,
             relationship_type, source, confidence, metadata, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (
            str(uuid.uuid4()),
            entity_a, entity_a_type,
            entity_b, entity_b_type,
            rel_type, source, confidence,
            json.dumps(metadata, default=str) if metadata else None,
        ))
        return True
    except Exception:
        return False


def build_relationships_from_events(limit=500):
    """
    Scan development_events and extract entity relationships.
    """
    conn = get_db()
    cur = conn.cursor()

    cur.execute('''
        SELECT id, event_type, city, state, parcel_id, developer,
               event_date, source, metadata, created_at
        FROM development_events
        ORDER BY created_at DESC
        LIMIT ?
    ''', (limit,))

    rows = cur.fetchall()
    if not rows:
        conn.close()
        print("[RelBuilder] No events to process.")
        return 0

    col_names = [d[0] for d in cur.description]
    created = 0

    for row in rows:
        event = dict(zip(col_names, row))
        entities = _extract_entities_from_event(event)
        event_type = event.get('event_type', '')
        city = event.get('city', '')
        state = event.get('state', '')
        location = f"{city}, {state}" if city else None

        # Developer → parcel relationships
        for dev in entities['developers']:
            for parcel in entities['parcels']:
                if event_type == 'LAND_PURCHASE':
                    if _store_relationship(cur, dev, 'developer', parcel, 'parcel',
                                           REL_LLC_PURCHASED_PARCEL, event.get('id'), 70):
                        created += 1

            # Developer → city association
            if location:
                if _store_relationship(cur, dev, 'developer', location, 'city',
                                       REL_DEVELOPER_ACTIVE_IN_CITY, event.get('id'), 60):
                    created += 1

            # Developer → project association (for any project-related event)
            if event_type in ('ZONING_CASE', 'SUBDIVISION_PLAT', 'PERMIT_APPLICATION'):
                project_key = f"{city}_{state}_{dev}".lower().replace(' ', '_')
                if _store_relationship(cur, dev, 'developer', project_key, 'project',
                                       REL_DEVELOPER_ASSOCIATED_PROJECT, event.get('id'), 65):
                    created += 1

        # Parcel → permit relationships
        for parcel in entities['parcels']:
            if event_type == 'PERMIT_APPLICATION':
                if _store_relationship(cur, parcel, 'parcel', event.get('id'), 'permit',
                                       REL_PARCEL_HAS_PERMIT, event.get('id'), 75):
                    created += 1

        # Contractor → parcel/project relationships
        for contractor in entities['contractors']:
            for parcel in entities['parcels']:
                if _store_relationship(cur, contractor, 'contractor', parcel, 'parcel',
                                       REL_CONTRACTOR_BIDDING_PROJECT, event.get('id'), 60):
                    created += 1
            if location:
                project_key = f"{city}_{state}_project".lower().replace(' ', '_')
                if _store_relationship(cur, contractor, 'contractor', project_key, 'project',
                                       REL_CONTRACTOR_BIDDING_PROJECT, event.get('id'), 55):
                    created += 1

        # Consultant → project relationships
        for consultant in entities['consultants']:
            if location:
                project_key = f"{city}_{state}_project".lower().replace(' ', '_')
                if _store_relationship(cur, consultant, 'consultant', project_key, 'project',
                                       REL_CONSULTANT_WORKING_PROJECT, event.get('id'), 50):
                    created += 1

        # Buyer/seller relationships
        for buyer in entities['buyers']:
            for parcel in entities['parcels']:
                if _store_relationship(cur, buyer, 'company', parcel, 'parcel',
                                       REL_LLC_PURCHASED_PARCEL, event.get('id'), 70):
                    created += 1
        for seller in entities['sellers']:
            for parcel in entities['parcels']:
                if _store_relationship(cur, seller, 'company', parcel, 'parcel',
                                       REL_PARCEL_SOLD_BY, event.get('id'), 60):
                    created += 1

    conn.commit()
    conn.close()
    print(f"[RelBuilder] Created {created} entity relationships from {len(rows)} events.")
    return created
