"""
Parcel Linker.
Converts addresses to parcel IDs, links property_signals to parcels,
and aggregates parcel activity.
"""
import json
import re
import uuid
from datetime import datetime

from db import get_db


def _normalize_address(address):
    """
    Normalize an address string for matching.
    Strips unit numbers, standardizes directionals, removes punctuation.
    """
    if not address:
        return ''
    addr = address.upper().strip()
    # Remove unit/suite/apt designators
    addr = re.sub(r'\s+(UNIT|STE|SUITE|APT|#)\s*\S+', '', addr)
    # Standardize directionals
    replacements = {
        ' NORTH ': ' N ', ' SOUTH ': ' S ',
        ' EAST ': ' E ', ' WEST ': ' W ',
        ' NORTHEAST ': ' NE ', ' NORTHWEST ': ' NW ',
        ' SOUTHEAST ': ' SE ', ' SOUTHWEST ': ' SW ',
    }
    for old, new in replacements.items():
        addr = addr.replace(old, new)
    # Standardize street types
    street_types = {
        ' STREET': ' ST', ' AVENUE': ' AVE', ' BOULEVARD': ' BLVD',
        ' DRIVE': ' DR', ' LANE': ' LN', ' ROAD': ' RD',
        ' PLACE': ' PL', ' COURT': ' CT', ' CIRCLE': ' CIR',
        ' HIGHWAY': ' HWY', ' PARKWAY': ' PKWY', ' TRAIL': ' TRL',
    }
    for old, new in street_types.items():
        addr = addr.replace(old, new)
    # Remove extra spaces and punctuation
    addr = re.sub(r'[.,]', '', addr)
    addr = re.sub(r'\s+', ' ', addr).strip()
    return addr


def _generate_parcel_id(address, city, state):
    """
    Generate a deterministic parcel ID from address components.
    Used when no official parcel ID is available.
    """
    normalized = _normalize_address(address)
    if not normalized:
        return None
    key = f"{normalized}|{(city or '').upper()}|{(state or '').upper()}"
    # Use a deterministic UUID based on address
    return str(uuid.uuid5(uuid.NAMESPACE_URL, key))


def link_signals_to_parcels():
    """
    Link property_signals to parcels.
    For signals without a parcel_id, generate one from the address.
    Create parcel records as needed.
    """
    conn = get_db()
    cur = conn.cursor()

    # Get signals missing parcel_id but having an address
    cur.execute('''
        SELECT id, address, city, state, entity_name, signal_type, metadata
        FROM property_signals
        WHERE (parcel_id IS NULL OR parcel_id = '')
        AND address IS NOT NULL AND address != ''
    ''')
    rows = cur.fetchall()
    cols = [d[0] for d in cur.description]

    linked = 0
    parcels_created = 0

    for row in rows:
        sig = dict(zip(cols, row))
        address = sig['address']
        city = sig['city']
        state = sig['state']

        # Try to find existing parcel by normalized address
        normalized = _normalize_address(address)
        parcel_id = None

        # Check if any existing parcel matches this address
        cur.execute('''
            SELECT parcel_id FROM parcels
            WHERE city = ? AND state = ?
        ''', (city, state))
        existing_parcels = cur.fetchall()

        for (existing_pid,) in existing_parcels:
            # Check parcels table for address match
            cur.execute('SELECT address FROM parcels WHERE parcel_id = ?', (existing_pid,))
            p_row = cur.fetchone()
            if p_row and p_row[0]:
                if _normalize_address(p_row[0]) == normalized:
                    parcel_id = existing_pid
                    break

        # If no match found, generate a parcel ID and create record
        if not parcel_id:
            parcel_id = _generate_parcel_id(address, city, state)
            if parcel_id:
                try:
                    cur.execute('''
                        INSERT OR IGNORE INTO parcels
                        (id, parcel_id, address, city, state, created_at)
                        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    ''', (str(uuid.uuid4()), parcel_id, address, city, state))
                    parcels_created += 1
                except Exception:
                    pass

        # Update the signal with the parcel_id
        if parcel_id:
            try:
                cur.execute('''
                    UPDATE property_signals SET parcel_id = ? WHERE id = ?
                ''', (parcel_id, sig['id']))
                linked += 1
            except Exception:
                pass

    conn.commit()
    conn.close()
    print(f"[ParcelLinker] Linked {linked} signals, created {parcels_created} new parcels")
    return {'linked': linked, 'parcels_created': parcels_created}


def aggregate_parcel_activity():
    """
    Aggregate signal activity per parcel.
    Updates development_probability based on signal count and types.
    """
    conn = get_db()
    cur = conn.cursor()

    # Get all parcels with their signal counts
    cur.execute('''
        SELECT p.parcel_id, p.city, p.state,
               COUNT(ps.id) as signal_count,
               GROUP_CONCAT(DISTINCT ps.signal_type) as signal_types
        FROM parcels p
        LEFT JOIN property_signals ps ON ps.parcel_id = p.parcel_id
        GROUP BY p.parcel_id
        HAVING signal_count > 0
    ''')
    rows = cur.fetchall()

    updated = 0
    for parcel_id, city, state, signal_count, signal_types_str in rows:
        signal_types = set((signal_types_str or '').split(','))

        # Base probability from signal diversity
        type_score = len(signal_types) * 10
        count_score = min(signal_count * 5, 30)
        base_prob = min(type_score + count_score, 60)

        try:
            cur.execute('''
                UPDATE parcels SET development_probability = ?
                WHERE parcel_id = ?
                AND (development_probability IS NULL OR development_probability < ?)
            ''', (base_prob, parcel_id, base_prob))
            updated += 1
        except Exception:
            pass

    conn.commit()
    conn.close()
    print(f"[ParcelLinker] Updated activity scores for {updated} parcels")
    return updated


def run_parcel_linker():
    """Full parcel linking cycle."""
    print(f"[ParcelLinker] START — {datetime.utcnow().isoformat()}")
    result = link_signals_to_parcels()
    activity = aggregate_parcel_activity()
    result['activity_updated'] = activity
    print(f"[ParcelLinker] COMPLETE")
    return result
