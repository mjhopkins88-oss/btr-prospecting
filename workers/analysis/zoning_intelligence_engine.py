"""
GIS Zoning Intelligence Engine.
Overlays parcel boundaries with zoning classifications to improve
development probability scoring.

Tasks:
  - Identify zoning classification for parcels
  - Calculate allowable density
  - Detect multifamily zoning compatibility
  - Update parcel intelligence scoring
"""
import json
import uuid
from datetime import datetime

from db import get_db


# Zoning categories favorable for BTR/multifamily
MULTIFAMILY_ZONING_CODES = {
    'MF', 'MF-1', 'MF-2', 'MF-3', 'MF-4',
    'R-3', 'R-4', 'R-5', 'R-6',
    'RM', 'RM-1', 'RM-2',
    'MU', 'MU-1', 'MU-2', 'MXD',
    'PD', 'PUD', 'PD-MF',
    'A', 'A-1', 'A-2',
    'TOD', 'TC', 'UC',
    'MH', 'RMH',
}

# Density-compatible codes (allow higher density)
HIGH_DENSITY_CODES = {
    'MF-3', 'MF-4', 'R-5', 'R-6', 'MU-2',
    'TOD', 'UC', 'PD', 'PUD',
}

# Zoning compatibility scores
ZONING_SCORES = {
    'multifamily': 25,
    'mixed_use': 20,
    'planned_development': 20,
    'high_density': 15,
    'single_family': 5,
    'commercial': 10,
    'industrial': 0,
    'agricultural': 0,
}


def _classify_zoning(zoning_code):
    """Classify a zoning code into a category."""
    if not zoning_code:
        return 'unknown'
    code = zoning_code.upper().strip()

    if any(code.startswith(p) for p in ['MF', 'RM', 'R-3', 'R-4', 'R-5', 'R-6', 'A-', 'MH']):
        return 'multifamily'
    if any(code.startswith(p) for p in ['MU', 'MXD', 'TOD', 'TC', 'UC']):
        return 'mixed_use'
    if any(code.startswith(p) for p in ['PD', 'PUD']):
        return 'planned_development'
    if any(code.startswith(p) for p in ['R-1', 'R-2', 'RS', 'SF']):
        return 'single_family'
    if any(code.startswith(p) for p in ['C-', 'C1', 'C2', 'B-', 'CR']):
        return 'commercial'
    if any(code.startswith(p) for p in ['I-', 'M-', 'LI', 'HI']):
        return 'industrial'
    if any(code.startswith(p) for p in ['AG', 'A-']):
        return 'agricultural'
    return 'unknown'


def _calculate_density_score(zoning_code, acreage=None):
    """Calculate a density compatibility score for BTR/multifamily."""
    category = _classify_zoning(zoning_code)
    base_score = ZONING_SCORES.get(category, 5)

    # Bonus for high-density codes
    if zoning_code and zoning_code.upper().strip() in HIGH_DENSITY_CODES:
        base_score += 10

    # Bonus for large acreage in appropriate zoning
    if acreage and category in ('multifamily', 'mixed_use', 'planned_development'):
        if acreage >= 20:
            base_score += 10
        elif acreage >= 10:
            base_score += 5

    return min(base_score, 35)


def analyze_parcel_zoning():
    """
    Analyze zoning classifications for all parcels and update
    development probability with zoning compatibility scores.
    """
    conn = get_db()
    cur = conn.cursor()

    # Get parcels with zoning data
    try:
        cur.execute('''
            SELECT parcel_id, zoning_code, acreage, city, state
            FROM parcels
            WHERE parcel_id IS NOT NULL
        ''')
        parcels = cur.fetchall()
    except Exception as e:
        print(f"[ZoningEngine] Query error: {e}")
        conn.close()
        return {'parcels_analyzed': 0}

    analyzed = 0
    multifamily_compatible = 0

    for parcel_id, zoning_code, acreage, city, state in parcels:
        if not zoning_code:
            continue

        category = _classify_zoning(zoning_code)
        density_score = _calculate_density_score(zoning_code, acreage)

        is_mf_compatible = category in ('multifamily', 'mixed_use', 'planned_development')
        if is_mf_compatible:
            multifamily_compatible += 1

        # Store zoning analysis in parcel context
        try:
            cur.execute('''
                SELECT id FROM parcel_context WHERE parcel_id = ? LIMIT 1
            ''', (parcel_id,))
            existing = cur.fetchone()

            zoning_data = json.dumps({
                'zoning_code': zoning_code,
                'zoning_category': category,
                'density_score': density_score,
                'multifamily_compatible': is_mf_compatible,
                'analyzed_at': datetime.utcnow().isoformat(),
            })

            if existing:
                cur.execute('''
                    UPDATE parcel_context SET zoning_analysis = ?
                    WHERE parcel_id = ?
                ''', (zoning_data, parcel_id))
            else:
                cur.execute('''
                    INSERT OR IGNORE INTO parcel_context
                    (id, parcel_id, zoning_analysis, created_at)
                    VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ''', (str(uuid.uuid4()), parcel_id, zoning_data))

            analyzed += 1
        except Exception:
            pass

    conn.commit()
    conn.close()

    print(f"[ZoningEngine] Analyzed {analyzed} parcels, "
          f"{multifamily_compatible} multifamily-compatible")
    return {
        'parcels_analyzed': analyzed,
        'multifamily_compatible': multifamily_compatible,
    }


def run_zoning_intelligence():
    """Full zoning intelligence cycle."""
    print(f"[ZoningEngine] START — {datetime.utcnow().isoformat()}")
    result = analyze_parcel_zoning()
    print(f"[ZoningEngine] COMPLETE")
    return result
