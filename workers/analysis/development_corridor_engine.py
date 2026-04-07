"""
Development Corridor Detection Engine.
Detects geographic regions where development activity is clustering,
identifying corridors of active development along highways, near population
growth areas, and infrastructure expansion zones.

Uses signals:
  - permits
  - zoning requests
  - plat filings
  - land purchases
  - construction financing
  - contractor activity

When clustering exceeds threshold, creates a DEVELOPMENT_CORRIDOR signal.
"""
import json
import math
import uuid
from collections import defaultdict
from datetime import datetime, timedelta

from db import get_db


# ---------------------------------------------------------------------------
# City coordinates (reuse from geographic_cluster_detector)
# ---------------------------------------------------------------------------
CITY_COORDS = {
    'phoenix': (33.4484, -112.0740),
    'scottsdale': (33.4942, -111.9261),
    'mesa': (33.4152, -111.8315),
    'chandler': (33.3062, -111.8413),
    'gilbert': (33.3528, -111.7890),
    'tempe': (33.4255, -111.9400),
    'glendale': (33.5387, -112.1860),
    'goodyear': (33.4353, -112.3577),
    'surprise': (33.6292, -112.3680),
    'dallas': (32.7767, -96.7970),
    'fort worth': (32.7555, -97.3308),
    'frisco': (33.1507, -96.8236),
    'mckinney': (33.1972, -96.6397),
    'plano': (33.0198, -96.6989),
    'arlington': (32.7357, -97.1081),
    'atlanta': (33.7490, -84.3880),
    'charlotte': (35.2271, -80.8431),
    'nashville': (36.1627, -86.7816),
    'tampa': (27.9506, -82.4572),
    'orlando': (28.5383, -81.3792),
    'denver': (39.7392, -104.9903),
    'raleigh': (35.7796, -78.6382),
    'austin': (30.2672, -97.7431),
    'san antonio': (29.4241, -98.4936),
    'houston': (29.7604, -95.3698),
    'jacksonville': (30.3322, -81.6557),
    'greenville': (34.8526, -82.3940),
    'spartanburg': (34.9496, -81.9320),
    'columbia': (34.0007, -81.0348),
    'charleston': (32.7765, -79.9311),
    'savannah': (32.0809, -81.0912),
    'huntsville': (34.7304, -86.5861),
    'birmingham': (33.5207, -86.8025),
    'knoxville': (35.9606, -83.9207),
    'boise': (43.6150, -116.2023),
    'las vegas': (36.1699, -115.1398),
    'salt lake city': (40.7608, -111.8910),
    'tucson': (32.2226, -110.9747),
}

# Known highway corridors in target markets
KNOWN_CORRIDORS = {
    'I-10 Phoenix West': {'cities': ['phoenix', 'goodyear', 'surprise'], 'state': 'AZ'},
    'Loop 202 Southeast': {'cities': ['mesa', 'gilbert', 'chandler'], 'state': 'AZ'},
    'I-35 DFW North': {'cities': ['dallas', 'frisco', 'mckinney', 'plano'], 'state': 'TX'},
    'I-30 DFW West': {'cities': ['dallas', 'fort worth', 'arlington'], 'state': 'TX'},
    'I-35 Austin-San Antonio': {'cities': ['austin', 'san antonio'], 'state': 'TX'},
    'I-85 Charlotte-Greenville': {'cities': ['charlotte', 'greenville', 'spartanburg'], 'state': 'NC'},
    'I-40 Raleigh Triangle': {'cities': ['raleigh'], 'state': 'NC'},
    'I-75 Atlanta South': {'cities': ['atlanta'], 'state': 'GA'},
    'I-4 Tampa-Orlando': {'cities': ['tampa', 'orlando'], 'state': 'FL'},
    'I-65 Nashville': {'cities': ['nashville'], 'state': 'TN'},
    'I-25 Denver Front Range': {'cities': ['denver'], 'state': 'CO'},
}

MILES_PER_DEG_LAT = 69.0
CORRIDOR_SIGNAL_TYPES = {
    'BUILDING_PERMIT', 'MULTIFAMILY_PERMIT', 'SUBDIVISION_PERMIT',
    'SITE_DEVELOPMENT_PERMIT', 'RESIDENTIAL_COMPLEX_PERMIT',
    'ZONING_AGENDA_ITEM', 'REZONING_REQUEST', 'SUBDIVISION_APPLICATION',
    'SUBDIVISION_PLAT', 'PRELIMINARY_PLAT', 'FINAL_PLAT',
    'LAND_PURCHASE', 'DEED_TRANSFER',
    'CONSTRUCTION_FINANCING', 'COMMERCIAL_MORTGAGE',
    'CONTRACTOR_BID', 'SITE_PLAN_PREP', 'ENGINEERING_PLAN_SUBMISSION',
    'CIVIL_ENGINEERING_PLAN', 'SITE_PREP_ACTIVITY',
    'INFRASTRUCTURE_BID',
}

# Minimum signals in a corridor region to qualify
MIN_CORRIDOR_SIGNALS = 5
# How far back to look (days)
LOOKBACK_DAYS = 180


# ---------------------------------------------------------------------------
# Geo helpers
# ---------------------------------------------------------------------------

def _haversine_miles(lat1, lon1, lat2, lon2):
    """Approximate distance in miles between two lat/lon points."""
    d_lat = math.radians(lat2 - lat1)
    d_lon = math.radians(lon2 - lon1)
    a = (math.sin(d_lat / 2) ** 2 +
         math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *
         math.sin(d_lon / 2) ** 2)
    c = 2 * math.asin(math.sqrt(a))
    return 3959 * c  # Earth radius in miles


def _get_signal_coords(signal):
    """Get coordinates for a signal — from parcel or city lookup."""
    lat = signal.get('latitude')
    lon = signal.get('longitude')
    if lat and lon:
        try:
            return float(lat), float(lon)
        except (ValueError, TypeError):
            pass

    city = (signal.get('city') or '').strip().lower()
    if city in CITY_COORDS:
        return CITY_COORDS[city]

    return None, None


# ---------------------------------------------------------------------------
# Corridor detection
# ---------------------------------------------------------------------------

def _collect_corridor_signals():
    """Gather geo-located signals for corridor analysis."""
    conn = get_db()
    cur = conn.cursor()

    cutoff = (datetime.utcnow() - timedelta(days=LOOKBACK_DAYS)).isoformat()

    cur.execute('''
        SELECT ps.id, ps.signal_type, ps.city, ps.state, ps.entity_name,
               ps.created_at, p.latitude, p.longitude
        FROM property_signals ps
        LEFT JOIN parcels p ON p.parcel_id = ps.parcel_id
        WHERE ps.created_at >= ?
        ORDER BY ps.created_at DESC
    ''', (cutoff,))
    rows = cur.fetchall()
    conn.close()

    signals = []
    for row in rows:
        sig = {
            'id': row[0],
            'signal_type': row[1],
            'city': row[2],
            'state': row[3],
            'entity_name': row[4],
            'created_at': row[5],
            'latitude': row[6],
            'longitude': row[7],
        }
        if sig['signal_type'] in CORRIDOR_SIGNAL_TYPES:
            signals.append(sig)

    return signals


def _detect_corridors_by_known_routes(signals):
    """Detect corridors based on known highway routes."""
    corridors = []

    for corridor_name, config in KNOWN_CORRIDORS.items():
        corridor_cities = set(config['cities'])
        corridor_state = config['state']

        # Find signals in this corridor
        corridor_signals = []
        for sig in signals:
            city = (sig.get('city') or '').strip().lower()
            state = (sig.get('state') or '').strip().upper()
            if city in corridor_cities or state == corridor_state:
                lat, lon = _get_signal_coords(sig)
                if lat and lon:
                    # Check if within ~30 miles of any corridor city
                    for cc in corridor_cities:
                        if cc in CITY_COORDS:
                            cc_lat, cc_lon = CITY_COORDS[cc]
                            dist = _haversine_miles(lat, lon, cc_lat, cc_lon)
                            if dist <= 30:
                                corridor_signals.append(sig)
                                break

        if len(corridor_signals) >= MIN_CORRIDOR_SIGNALS:
            # Calculate signal density and growth rate
            signal_density = len(corridor_signals)

            # Growth rate: compare recent 30d vs prior 30d
            now = datetime.utcnow()
            recent_cutoff = (now - timedelta(days=30)).isoformat()
            prior_cutoff = (now - timedelta(days=60)).isoformat()

            recent = sum(1 for s in corridor_signals
                         if str(s.get('created_at', '')) >= recent_cutoff)
            prior = sum(1 for s in corridor_signals
                        if prior_cutoff <= str(s.get('created_at', '')) < recent_cutoff)
            growth_rate = ((recent - prior) / max(prior, 1)) * 100

            # Determine dominant development type
            type_counts = defaultdict(int)
            for s in corridor_signals:
                type_counts[s['signal_type']] += 1
            dominant_type = max(type_counts, key=type_counts.get) if type_counts else 'MIXED'

            corridors.append({
                'corridor_name': corridor_name,
                'city': ', '.join(c.title() for c in corridor_cities),
                'state': corridor_state,
                'signal_density': signal_density,
                'growth_rate': round(growth_rate, 1),
                'dominant_development_type': dominant_type,
                'signal_types': dict(type_counts),
            })

    return corridors


def _detect_corridors_by_clustering(signals):
    """
    Detect ad-hoc corridors through spatial clustering.
    Groups signals by proximity and identifies dense clusters.
    """
    corridors = []

    # Group signals by state and approximate region
    geo_signals = []
    for sig in signals:
        lat, lon = _get_signal_coords(sig)
        if lat and lon:
            geo_signals.append({**sig, 'lat': lat, 'lon': lon})

    if len(geo_signals) < MIN_CORRIDOR_SIGNALS:
        return corridors

    # Simple grid-based clustering (0.5 degree cells ~ 30 miles)
    grid = defaultdict(list)
    for sig in geo_signals:
        cell = (round(sig['lat'] * 2) / 2, round(sig['lon'] * 2) / 2)
        grid[cell].append(sig)

    for cell, cell_signals in grid.items():
        if len(cell_signals) < MIN_CORRIDOR_SIGNALS:
            continue

        # Check adjacent cells too
        adj_signals = list(cell_signals)
        for dx in [-0.5, 0, 0.5]:
            for dy in [-0.5, 0, 0.5]:
                if dx == 0 and dy == 0:
                    continue
                adj_cell = (cell[0] + dx, cell[1] + dy)
                if adj_cell in grid:
                    adj_signals.extend(grid[adj_cell])

        if len(adj_signals) < MIN_CORRIDOR_SIGNALS * 2:
            continue

        # Build corridor from cluster
        cities = set()
        states = set()
        type_counts = defaultdict(int)
        for s in adj_signals:
            if s.get('city'):
                cities.add(s['city'])
            if s.get('state'):
                states.add(s['state'])
            type_counts[s['signal_type']] += 1

        state_str = ', '.join(sorted(states)) if states else 'Unknown'
        city_str = ', '.join(sorted(cities)[:5]) if cities else f"Region {cell[0]:.1f},{cell[1]:.1f}"

        # Growth rate
        now = datetime.utcnow()
        recent = sum(1 for s in adj_signals
                     if str(s.get('created_at', '')) >= (now - timedelta(days=30)).isoformat())
        prior = sum(1 for s in adj_signals
                    if (now - timedelta(days=60)).isoformat() <= str(s.get('created_at', '')) < (now - timedelta(days=30)).isoformat())
        growth_rate = ((recent - prior) / max(prior, 1)) * 100

        dominant = max(type_counts, key=type_counts.get) if type_counts else 'MIXED'

        corridor_name = f"Emerging Corridor: {city_str}"
        corridors.append({
            'corridor_name': corridor_name,
            'city': city_str,
            'state': state_str,
            'signal_density': len(adj_signals),
            'growth_rate': round(growth_rate, 1),
            'dominant_development_type': dominant,
            'signal_types': dict(type_counts),
        })

    return corridors


# ---------------------------------------------------------------------------
# Store corridors
# ---------------------------------------------------------------------------

def _store_corridors(corridors):
    """Store detected corridors in the database."""
    conn = get_db()
    cur = conn.cursor()

    stored = 0
    for corridor in corridors:
        # Check if corridor already exists
        cur.execute('''
            SELECT id FROM development_corridors
            WHERE corridor_name = ?
        ''', (corridor['corridor_name'],))
        existing = cur.fetchone()

        metadata = json.dumps({
            'signal_types': corridor.get('signal_types', {}),
        })

        if existing:
            cur.execute('''
                UPDATE development_corridors
                SET signal_density = ?,
                    growth_rate = ?,
                    dominant_development_type = ?,
                    metadata = ?,
                    updated_at = ?
                WHERE id = ?
            ''', (corridor['signal_density'], corridor['growth_rate'],
                  corridor['dominant_development_type'], metadata,
                  datetime.utcnow().isoformat(), existing[0]))
        else:
            cur.execute('''
                INSERT INTO development_corridors
                    (id, corridor_name, city, state, signal_density,
                     growth_rate, dominant_development_type, metadata, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (str(uuid.uuid4()), corridor['corridor_name'],
                  corridor['city'], corridor['state'],
                  corridor['signal_density'], corridor['growth_rate'],
                  corridor['dominant_development_type'], metadata,
                  datetime.utcnow().isoformat()))

        # Also create a DEVELOPMENT_CORRIDOR signal for radar map
        cur.execute('''
            SELECT id FROM property_signals
            WHERE signal_type = 'DEVELOPMENT_CORRIDOR'
            AND city = ? AND state = ?
        ''', (corridor['city'], corridor['state']))

        if not cur.fetchone():
            cur.execute('''
                INSERT INTO property_signals
                    (id, signal_type, city, state, entity_name, metadata, created_at)
                VALUES (?, 'DEVELOPMENT_CORRIDOR', ?, ?, ?, ?, ?)
            ''', (str(uuid.uuid4()), corridor['city'], corridor['state'],
                  corridor['corridor_name'], metadata,
                  datetime.utcnow().isoformat()))

        stored += 1

    conn.commit()
    conn.close()
    return stored


# ---------------------------------------------------------------------------
# Query helpers for dashboard
# ---------------------------------------------------------------------------

def get_active_corridors(limit=20):
    """Get active development corridors for the dashboard."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute('''
        SELECT corridor_name, city, state, signal_density,
               growth_rate, dominant_development_type, created_at
        FROM development_corridors
        ORDER BY signal_density DESC, growth_rate DESC
        LIMIT ?
    ''', (limit,))
    rows = cur.fetchall()
    conn.close()

    return [{
        'corridor_name': r[0],
        'city': r[1],
        'state': r[2],
        'signal_density': r[3],
        'growth_rate': r[4],
        'dominant_development_type': r[5],
        'created_at': r[6],
    } for r in rows]


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_development_corridor_engine():
    """
    Main entry point — detect development corridors from signal clustering.
    """
    print("[CorridorEngine] Starting development corridor detection...")

    # Step 1: Collect signals
    signals = _collect_corridor_signals()
    print(f"[CorridorEngine] Collected {len(signals)} geo-located signals")

    if not signals:
        print("[CorridorEngine] No signals found — skipping")
        return {'corridors_detected': 0}

    # Step 2: Detect corridors from known routes
    known_corridors = _detect_corridors_by_known_routes(signals)
    print(f"[CorridorEngine] Detected {len(known_corridors)} known corridor matches")

    # Step 3: Detect ad-hoc corridors via spatial clustering
    cluster_corridors = _detect_corridors_by_clustering(signals)
    print(f"[CorridorEngine] Detected {len(cluster_corridors)} emerging corridors")

    # Step 4: Merge and deduplicate
    all_corridors = known_corridors + cluster_corridors
    seen = set()
    unique_corridors = []
    for c in all_corridors:
        key = c['corridor_name']
        if key not in seen:
            seen.add(key)
            unique_corridors.append(c)

    # Step 5: Store corridors
    stored = _store_corridors(unique_corridors)
    print(f"[CorridorEngine] Stored {stored} development corridors")

    result = {
        'signals_analyzed': len(signals),
        'known_corridors': len(known_corridors),
        'emerging_corridors': len(cluster_corridors),
        'corridors_stored': stored,
    }
    print(f"[CorridorEngine] Complete: {result}")
    return result


if __name__ == '__main__':
    run_development_corridor_engine()
