"""
Geographic Cluster Detector.
Detects geographic clusters of development events — when 3+ events occur
within a ~10 mile radius within 120 days, it indicates a development hotspot.

Uses approximate lat/lon estimation from city names (no external geocoding API).
Falls back to city-name grouping when coordinates are unavailable.
"""
import math
from datetime import datetime, timedelta
from db import get_db


# ---------------------------------------------------------------------------
# Approximate city coordinates for BTR target markets
# (avoids external geocoding dependency)
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

# Approximate miles per degree at US latitudes
MILES_PER_DEG_LAT = 69.0
MILES_PER_DEG_LON = 54.6  # approximate at ~35°N


def _get_coords(city):
    """Get approximate coordinates for a city name."""
    if not city:
        return None
    return CITY_COORDS.get(city.strip().lower())


def _haversine_miles(lat1, lon1, lat2, lon2):
    """Approximate distance in miles between two lat/lon points."""
    dlat = abs(lat2 - lat1) * MILES_PER_DEG_LAT
    dlon = abs(lon2 - lon1) * MILES_PER_DEG_LON
    return math.sqrt(dlat**2 + dlon**2)


def detect_clusters(radius_miles=10, window_days=120, min_events=3):
    """
    Detect geographic clusters of development events.

    Returns list of cluster dicts:
    {
        'city': str,
        'state': str,
        'event_count': int,
        'event_types': list,
        'window_days': int,
        'cluster_detected': True,
    }
    """
    conn = get_db()
    cur = conn.cursor()

    cutoff = (datetime.utcnow() - timedelta(days=window_days + 60)).isoformat()
    cur.execute('''
        SELECT id, event_type, city, state, event_date, developer, created_at
        FROM development_events
        WHERE created_at >= ?
        ORDER BY event_date ASC
    ''', (cutoff,))

    rows = cur.fetchall()
    conn.close()

    if not rows:
        print("[ClusterDetector] No events to analyze.")
        return []

    col_names = [d[0] for d in cur.description]
    events = [dict(zip(col_names, r)) for r in rows]

    # Group events by approximate geographic proximity
    # Strategy: group by city+state, then check if nearby cities form clusters
    city_groups = {}
    for e in events:
        city = (e.get('city') or '').strip().lower()
        state = (e.get('state') or '').strip().upper()
        if city:
            key = (city, state)
            city_groups.setdefault(key, []).append(e)

    clusters = []

    # First: check single-city clusters (3+ events in same city within window)
    for (city, state), group_events in city_groups.items():
        if len(group_events) < min_events:
            continue

        # Check time window
        dates = _extract_dates(group_events)
        if len(dates) < min_events:
            continue

        dates.sort()
        # Use sliding window to find densest cluster
        for i in range(len(dates)):
            window_end = dates[i] + timedelta(days=window_days)
            in_window = [d for d in dates if dates[i] <= d <= window_end]
            if len(in_window) >= min_events:
                event_types = list(set(
                    e.get('event_type') for e in group_events
                    if e.get('event_type')
                ))
                actual_window = (max(in_window) - min(in_window)).days
                clusters.append({
                    'city': city.title(),
                    'state': state,
                    'event_count': len(in_window),
                    'event_types': event_types,
                    'window_days': actual_window,
                    'cluster_detected': True,
                })
                break  # one cluster per city

    # Second: check nearby-city clusters (cities within radius_miles)
    city_keys = list(city_groups.keys())
    merged_nearby = set()

    for i, (city1, state1) in enumerate(city_keys):
        if (city1, state1) in merged_nearby:
            continue
        coords1 = _get_coords(city1)
        if not coords1:
            continue

        nearby_events = list(city_groups[(city1, state1)])

        for j in range(i + 1, len(city_keys)):
            city2, state2 = city_keys[j]
            if state1 != state2:
                continue
            coords2 = _get_coords(city2)
            if not coords2:
                continue

            dist = _haversine_miles(coords1[0], coords1[1], coords2[0], coords2[1])
            if dist <= radius_miles:
                nearby_events.extend(city_groups[(city2, state2)])
                merged_nearby.add((city2, state2))

        if len(nearby_events) >= min_events and (city1, state1) not in merged_nearby:
            dates = _extract_dates(nearby_events)
            if len(dates) >= min_events:
                dates.sort()
                actual_window = (max(dates) - min(dates)).days
                if actual_window <= window_days:
                    event_types = list(set(
                        e.get('event_type') for e in nearby_events
                        if e.get('event_type')
                    ))
                    # Don't duplicate if already detected as single-city cluster
                    already = any(
                        c['city'].lower() == city1 and c['state'] == state1
                        for c in clusters
                    )
                    if not already:
                        clusters.append({
                            'city': city1.title(),
                            'state': state1,
                            'event_count': len(nearby_events),
                            'event_types': event_types,
                            'window_days': actual_window,
                            'cluster_detected': True,
                        })

    print(f"[ClusterDetector] Detected {len(clusters)} geographic clusters.")
    return clusters


def _extract_dates(events):
    """Extract datetime objects from event dicts."""
    dates = []
    for e in events:
        d = e.get('event_date') or e.get('created_at')
        if d:
            try:
                if isinstance(d, str):
                    dt = datetime.fromisoformat(d.replace('Z', '+00:00').replace('+00:00', ''))
                else:
                    dt = d
                dates.append(dt)
            except Exception:
                pass
    return dates


def get_cluster_cities():
    """
    Return a set of (city_lower, state_upper) tuples that have active clusters.
    Used by the optimizer to flag predicted projects.
    """
    clusters = detect_clusters()
    return set(
        (c['city'].lower(), c['state'].upper())
        for c in clusters
    )
