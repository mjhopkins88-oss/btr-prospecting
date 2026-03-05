"""
Developer DNA Analyzer.
Analyzes developer_project_history to build behavioral profiles
stored in developer_dna_profiles.
"""
import json
import uuid
from collections import Counter
from datetime import datetime

from db import get_db


def _fetch_developers(cur):
    """Get all developers."""
    cur.execute('SELECT id, developer_name FROM developers')
    return [{'id': r[0], 'name': r[1]} for r in cur.fetchall()]


def _fetch_project_history(cur, developer_id):
    """Get project history for a developer."""
    cur.execute('''
        SELECT city, state, project_type, unit_count, square_feet,
               project_stage, first_detected
        FROM developer_project_history
        WHERE developer_id = ?
        ORDER BY first_detected ASC
    ''', (developer_id,))
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, row)) for row in cur.fetchall()]


def _calculate_preferred_markets(history):
    """Extract preferred states and cities from project history."""
    state_counts = Counter(p['state'] for p in history if p.get('state'))
    city_counts = Counter(
        f"{p['city']},{p['state']}" for p in history
        if p.get('city') and p.get('state')
    )
    # Top states and cities by frequency
    preferred_states = [s for s, _ in state_counts.most_common(5)]
    preferred_cities = [c for c, _ in city_counts.most_common(10)]
    return preferred_states, preferred_cities


def _calculate_average_project_size(history):
    """Calculate average unit count across projects."""
    sizes = [p['unit_count'] for p in history if p.get('unit_count') and p['unit_count'] > 0]
    if not sizes:
        return 0
    return int(sum(sizes) / len(sizes))


def _calculate_typical_unit_range(history):
    """Get min/max unit count range."""
    sizes = [p['unit_count'] for p in history if p.get('unit_count') and p['unit_count'] > 0]
    if not sizes:
        return [0, 0]
    return [min(sizes), max(sizes)]


def _calculate_project_types(history):
    """Get most common project types."""
    types = Counter(p['project_type'] for p in history if p.get('project_type'))
    return [t for t, _ in types.most_common(5)]


def _detect_expansion_rate(history):
    """
    Expansion rate = unique new markets entered per year.
    Higher rate means more aggressive geographic expansion.
    """
    if len(history) < 2:
        return 0.0

    dates = []
    markets_seen = set()
    new_market_dates = []

    for p in history:
        market = (p.get('city', ''), p.get('state', ''))
        detected = p.get('first_detected')
        if detected:
            if isinstance(detected, str):
                try:
                    detected = datetime.fromisoformat(detected.replace('Z', ''))
                except Exception:
                    continue
            dates.append(detected)
            if market not in markets_seen:
                markets_seen.add(market)
                new_market_dates.append(detected)

    if len(dates) < 2:
        return 0.0

    span_days = (max(dates) - min(dates)).days
    if span_days < 30:
        return 0.0

    span_years = span_days / 365.0
    return round(len(new_market_dates) / span_years, 2)


def build_dna_profile(cur, developer_id, history):
    """Build and store a DNA profile for a developer."""
    preferred_states, preferred_cities = _calculate_preferred_markets(history)
    avg_size = _calculate_average_project_size(history)
    unit_range = _calculate_typical_unit_range(history)
    project_types = _calculate_project_types(history)
    expansion_rate = _detect_expansion_rate(history)

    profile_id = str(uuid.uuid4())

    # Check if profile exists
    cur.execute('SELECT id FROM developer_dna_profiles WHERE developer_id = ?', (developer_id,))
    existing = cur.fetchone()

    if existing:
        cur.execute('''
            UPDATE developer_dna_profiles
            SET preferred_states = ?, preferred_cities = ?,
                typical_unit_range = ?, typical_project_types = ?,
                average_project_size = ?, expansion_rate = ?,
                last_updated = CURRENT_TIMESTAMP
            WHERE developer_id = ?
        ''', (
            json.dumps(preferred_states),
            json.dumps(preferred_cities),
            json.dumps(unit_range),
            json.dumps(project_types),
            avg_size,
            expansion_rate,
            developer_id,
        ))
    else:
        cur.execute('''
            INSERT INTO developer_dna_profiles
            (id, developer_id, preferred_states, preferred_cities,
             typical_unit_range, typical_project_types,
             average_project_size, expansion_rate)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            profile_id, developer_id,
            json.dumps(preferred_states),
            json.dumps(preferred_cities),
            json.dumps(unit_range),
            json.dumps(project_types),
            avg_size,
            expansion_rate,
        ))

    return {
        'developer_id': developer_id,
        'preferred_states': preferred_states,
        'preferred_cities': preferred_cities,
        'average_project_size': avg_size,
        'expansion_rate': expansion_rate,
    }


def run_dna_analysis():
    """
    Main entry point: analyze all developers and build DNA profiles.
    Also ingests developer data from development_events if developers table is sparse.
    """
    print(f"[DNA Analyzer] START — {datetime.utcnow().isoformat()}")

    conn = get_db()
    cur = conn.cursor()

    # Auto-ingest developers from development_events if developers table is sparse
    _ingest_developers_from_events(cur)
    _ingest_project_history_from_events(cur)

    developers = _fetch_developers(cur)
    print(f"[DNA Analyzer] Found {len(developers)} developers")

    profiles_built = 0
    for dev in developers:
        history = _fetch_project_history(cur, dev['id'])
        if not history:
            continue

        build_dna_profile(cur, dev['id'], history)
        profiles_built += 1

        # Update total_projects count
        cur.execute('''
            UPDATE developers SET total_projects = ? WHERE id = ?
        ''', (len(history), dev['id']))

    conn.commit()
    conn.close()

    print(f"[DNA Analyzer] COMPLETE — {profiles_built} profiles built")
    return {'profiles_built': profiles_built}


def _ingest_developers_from_events(cur):
    """
    Auto-populate developers table from development_events
    for any developer not already tracked.
    """
    cur.execute('''
        SELECT DISTINCT developer FROM development_events
        WHERE developer IS NOT NULL AND developer != ''
    ''')
    event_developers = [r[0] for r in cur.fetchall()]

    for dev_name in event_developers:
        cur.execute('SELECT id FROM developers WHERE developer_name = ?', (dev_name,))
        if not cur.fetchone():
            cur.execute('''
                INSERT INTO developers (id, developer_name)
                VALUES (?, ?)
            ''', (str(uuid.uuid4()), dev_name))


def _ingest_project_history_from_events(cur):
    """
    Auto-populate developer_project_history from development_events
    by grouping events by developer + city + state.
    """
    cur.execute('''
        SELECT d.id, d.developer_name FROM developers d
    ''')
    developers = [(r[0], r[1]) for r in cur.fetchall()]

    for dev_id, dev_name in developers:
        # Get distinct city/state combos from events
        cur.execute('''
            SELECT city, state, MIN(event_date) as first_date,
                   COUNT(*) as event_count
            FROM development_events
            WHERE developer = ?
            GROUP BY city, state
        ''', (dev_name,))
        projects = cur.fetchall()

        for city, state, first_date, event_count in projects:
            if not city or not state:
                continue
            # Check if already tracked
            cur.execute('''
                SELECT id FROM developer_project_history
                WHERE developer_id = ? AND city = ? AND state = ?
            ''', (dev_id, city, state))
            if cur.fetchone():
                continue

            # Try to extract project type and unit count from metadata
            project_type = None
            unit_count = None
            cur.execute('''
                SELECT event_type, metadata FROM development_events
                WHERE developer = ? AND city = ? AND state = ?
                AND metadata IS NOT NULL
                LIMIT 1
            ''', (dev_name, city, state))
            meta_row = cur.fetchone()
            if meta_row:
                project_type = meta_row[0]
                try:
                    meta = json.loads(meta_row[1]) if isinstance(meta_row[1], str) else meta_row[1]
                    unit_count = meta.get('unit_count') or meta.get('units')
                    if unit_count:
                        unit_count = int(unit_count)
                except Exception:
                    pass

            cur.execute('''
                INSERT INTO developer_project_history
                (id, developer_id, project_name, city, state, project_type,
                 unit_count, first_detected)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                str(uuid.uuid4()), dev_id,
                f"{dev_name} - {city}, {state}",
                city, state, project_type, unit_count, first_date,
            ))
