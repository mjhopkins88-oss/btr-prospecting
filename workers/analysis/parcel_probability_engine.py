"""
Parcel Development Probability Engine.
Analyzes parcel characteristics and context to calculate
development probability scores (0-100).
"""
import json
import uuid
from datetime import datetime

from db import get_db


# Zoning types that indicate development flexibility
FLEXIBLE_ZONING = {
    'residential', 'mixed_use', 'flex', 'planned_development',
    'commercial', 'industrial', 'r-3', 'r-4', 'r-5', 'pud',
    'mf', 'multifamily', 'multi-family',
}


def score_parcel(parcel, context):
    """
    Calculate development probability score for a parcel.

    Scoring variables:
    - acreage >= 10: +20
    - nearby_developments >= 3: +20
    - population_growth >= 2%: +20
    - permit_growth >= 10%: +15
    - infrastructure_projects >= 1: +15
    - zoning in flexible types: +10

    Returns (score, reasoning_parts).
    """
    score = 0
    reasoning = []

    acreage = parcel.get('acreage') or 0
    zoning = (parcel.get('zoning') or '').lower().strip()

    nearby_devs = context.get('nearby_developments') or 0
    pop_growth = context.get('population_growth') or 0
    permit_growth = context.get('permit_growth') or 0
    infra_projects = context.get('infrastructure_projects') or 0

    if acreage >= 10:
        score += 20
        if acreage >= 20:
            reasoning.append(f"Large parcel ({acreage:.1f} acres)")
        else:
            reasoning.append(f"Parcel size {acreage:.1f} acres suitable for development")

    if nearby_devs >= 3:
        score += 20
        reasoning.append(f"{nearby_devs} nearby developments indicate active corridor")

    if pop_growth >= 2:
        score += 20
        reasoning.append(f"High population growth ({pop_growth:.1f}%) in surrounding area")

    if permit_growth >= 10:
        score += 15
        reasoning.append(f"Permit activity growth of {permit_growth:.1f}%")

    if infra_projects >= 1:
        score += 15
        reasoning.append(f"{infra_projects} infrastructure project(s) nearby")

    if zoning in FLEXIBLE_ZONING:
        score += 10
        reasoning.append(f"Zoning ({zoning}) allows residential/mixed development")

    probability_score = min(score, 100)
    return probability_score, reasoning


def infer_development_type(parcel, context, score):
    """Infer likely development type from parcel characteristics."""
    acreage = parcel.get('acreage') or 0
    zoning = (parcel.get('zoning') or '').lower().strip()

    types = []

    if acreage >= 20 and score >= 60:
        types.append('Build-to-Rent')
    if acreage >= 10:
        types.append('Multifamily')
    if acreage >= 5:
        types.append('Townhomes')
    if zoning in ('mixed_use', 'flex', 'commercial'):
        types.append('Mixed-Use')
    if zoning in ('industrial',):
        types.append('Industrial')

    if not types:
        types.append('Residential')

    return ', '.join(types[:3])


def score_likelihood_label(score):
    """Convert probability score to human-readable likelihood."""
    if score >= 85:
        return 'Very High'
    if score >= 70:
        return 'High'
    if score >= 50:
        return 'Moderate'
    if score >= 30:
        return 'Low'
    return 'Very Low'


def run_probability_engine():
    """
    Main entry point: score all parcels with available context.
    Also auto-populates parcels from development_events if needed.
    """
    print(f"[Parcel Engine] START — {datetime.utcnow().isoformat()}")

    conn = get_db()
    cur = conn.cursor()

    # Auto-ingest parcels from development_events
    _ingest_parcels_from_events(cur)
    # Auto-build context from available data
    _build_parcel_context(cur)

    # Get all parcels with context
    cur.execute('''
        SELECT p.parcel_id, p.acreage, p.zoning, p.city, p.state,
               pc.nearby_developments, pc.population_growth,
               pc.permit_growth, pc.infrastructure_projects
        FROM parcels p
        LEFT JOIN parcel_context pc ON pc.parcel_id = p.parcel_id
    ''')
    cols = [d[0] for d in cur.description]
    rows = cur.fetchall()

    scored = 0
    for row in rows:
        data = dict(zip(cols, row))
        parcel_id = data['parcel_id']
        if not parcel_id:
            continue

        parcel = {
            'acreage': data.get('acreage'),
            'zoning': data.get('zoning'),
        }
        context = {
            'nearby_developments': data.get('nearby_developments'),
            'population_growth': data.get('population_growth'),
            'permit_growth': data.get('permit_growth'),
            'infrastructure_projects': data.get('infrastructure_projects'),
        }

        probability_score, reasoning_parts = score_parcel(parcel, context)
        dev_type = infer_development_type(parcel, context, probability_score)
        reasoning_text = '. '.join(reasoning_parts) if reasoning_parts else 'Insufficient data for detailed reasoning'

        # Upsert into parcel_development_probability
        cur.execute('''
            SELECT id FROM parcel_development_probability WHERE parcel_id = ?
        ''', (parcel_id,))
        existing = cur.fetchone()

        if existing:
            cur.execute('''
                UPDATE parcel_development_probability
                SET probability_score = ?, likely_development_type = ?,
                    reasoning = ?, created_at = CURRENT_TIMESTAMP
                WHERE parcel_id = ?
            ''', (probability_score, dev_type, reasoning_text, parcel_id))
        else:
            cur.execute('''
                INSERT INTO parcel_development_probability
                (id, parcel_id, probability_score, likely_development_type, reasoning)
                VALUES (?, ?, ?, ?, ?)
            ''', (str(uuid.uuid4()), parcel_id, probability_score, dev_type, reasoning_text))

        # Log
        cur.execute('''
            INSERT INTO parcel_probability_log
            (id, parcel_id, probability_score, notes)
            VALUES (?, ?, ?, ?)
        ''', (str(uuid.uuid4()), parcel_id, probability_score, reasoning_text))

        scored += 1

        # Log high-probability parcels to intelligence feed
        if probability_score >= 70:
            try:
                from app import log_intelligence_event
                log_intelligence_event(
                    event_type='PARCEL_ALERT',
                    title=f"NEW PARCEL ALERT \u2014 {parcel.get('city', 'Unknown')}",
                    description=f"High development probability detected ({probability_score}%): {dev_type}",
                    city=parcel.get('city'),
                    state=parcel.get('state'),
                    related_entity=parcel_id,
                    entity_id=parcel_id,
                )
            except Exception:
                pass

    conn.commit()
    conn.close()

    print(f"[Parcel Engine] COMPLETE — {scored} parcels scored")
    return {'parcels_scored': scored}


def _ingest_parcels_from_events(cur):
    """Auto-populate parcels table from development_events parcel_ids."""
    cur.execute('''
        SELECT DISTINCT parcel_id, city, state FROM development_events
        WHERE parcel_id IS NOT NULL AND parcel_id != ''
    ''')
    event_parcels = cur.fetchall()

    added = 0
    for parcel_id, city, state in event_parcels:
        cur.execute('SELECT id FROM parcels WHERE parcel_id = ?', (parcel_id,))
        if cur.fetchone():
            continue

        # Try to extract acreage/zoning from event metadata
        acreage = None
        zoning = None
        cur.execute('''
            SELECT metadata FROM development_events
            WHERE parcel_id = ? AND metadata IS NOT NULL LIMIT 1
        ''', (parcel_id,))
        meta_row = cur.fetchone()
        if meta_row:
            try:
                meta = json.loads(meta_row[0]) if isinstance(meta_row[0], str) else meta_row[0]
                acreage = meta.get('acreage') or meta.get('acres')
                if acreage:
                    acreage = float(acreage)
                zoning = meta.get('zoning') or meta.get('zone')
            except Exception:
                pass

        cur.execute('''
            INSERT INTO parcels (id, parcel_id, city, state, acreage, zoning)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (str(uuid.uuid4()), parcel_id, city, state, acreage, zoning))
        added += 1

    if added:
        print(f"[Parcel Engine] Ingested {added} new parcels from events")


def _build_parcel_context(cur):
    """Build parcel context from available data sources."""
    cur.execute('SELECT parcel_id, city, state FROM parcels')
    all_parcels = cur.fetchall()

    for parcel_id, city, state in all_parcels:
        if not city or not state:
            continue

        # Check if context already exists
        cur.execute('SELECT id FROM parcel_context WHERE parcel_id = ?', (parcel_id,))
        if cur.fetchone():
            continue

        # Count nearby developments (same city/state)
        cur.execute('''
            SELECT COUNT(DISTINCT developer) FROM development_events
            WHERE city = ? AND state = ? AND developer IS NOT NULL
        ''', (city, state))
        nearby_devs = cur.fetchone()[0]

        # Get population growth from city_growth_metrics if available
        pop_growth = 0
        permit_growth_val = 0
        try:
            cur.execute('''
                SELECT population_growth, permit_growth
                FROM city_growth_metrics
                WHERE city = ? AND state = ?
                LIMIT 1
            ''', (city, state))
            metrics = cur.fetchone()
            if metrics:
                pop_growth = metrics[0] or 0
                permit_growth_val = metrics[1] or 0
        except Exception:
            pass

        # Count infrastructure-related events
        cur.execute('''
            SELECT COUNT(*) FROM development_events
            WHERE city = ? AND state = ?
            AND event_type IN ('UTILITY_PLAN', 'UTILITY_EXTENSION',
                               'INFRASTRUCTURE', 'ROAD_IMPROVEMENT')
        ''', (city, state))
        infra = cur.fetchone()[0]

        # Development pressure = nearby_devs * 10 + infra * 15, capped at 100
        pressure = min(100, nearby_devs * 10 + infra * 15)

        cur.execute('''
            INSERT INTO parcel_context
            (id, parcel_id, nearby_developments, population_growth,
             permit_growth, infrastructure_projects, development_pressure_score)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (str(uuid.uuid4()), parcel_id, nearby_devs,
              pop_growth, permit_growth_val, infra, pressure))
