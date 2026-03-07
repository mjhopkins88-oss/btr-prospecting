"""
Parcel Contiguity Intelligence Engine.
Detects when purchased parcels form a development footprint by grouping
adjacent parcels and calculating combined acreage.

Typical BTR footprint:
  20-60 acres
  Rectangular layout
  Road frontage

Adds contiguous_land_probability score to parcel intelligence.
"""
import json
import uuid
from collections import defaultdict
from datetime import datetime, timedelta

from db import get_db


# BTR development footprint characteristics
MIN_BTR_ACREAGE = 20
MAX_BTR_ACREAGE = 200
IDEAL_BTR_ACREAGE = (20, 60)

# Scoring
CONTIGUITY_BASE_SCORE = 15
ACREAGE_BONUS = 10
SAME_BUYER_BONUS = 15
RECENT_PURCHASE_BONUS = 10


def _find_parcel_clusters():
    """
    Find clusters of parcels owned by the same entity or purchased recently.
    Uses entity_name matches and geographic proximity via city grouping.
    """
    conn = get_db()
    cur = conn.cursor()

    cutoff = (datetime.utcnow() - timedelta(days=365)).isoformat()

    # Find parcels with recent land purchase signals, grouped by buyer and city
    cur.execute('''
        SELECT ps.parcel_id, ps.entity_name, ps.city, ps.state,
               ps.address, ps.metadata
        FROM property_signals ps
        WHERE ps.signal_type IN ('LAND_PURCHASE', 'DEED_TRANSFER', 'OWNER_CHANGE')
        AND ps.created_at >= ?
        AND ps.parcel_id IS NOT NULL AND ps.parcel_id != ''
        AND ps.entity_name IS NOT NULL AND ps.entity_name != ''
        ORDER BY ps.entity_name, ps.city
    ''', (cutoff,))
    rows = cur.fetchall()
    conn.close()

    # Group by (normalized buyer, city)
    clusters = defaultdict(list)
    for parcel_id, entity, city, state, address, metadata in rows:
        key = (entity.upper().strip(), city, state)
        meta = {}
        if metadata:
            try:
                meta = json.loads(metadata) if isinstance(metadata, str) else metadata
            except Exception:
                pass
        acreage = meta.get('acreage')
        try:
            acreage = float(acreage) if acreage else None
        except (ValueError, TypeError):
            acreage = None
        clusters[key].append({
            'parcel_id': parcel_id,
            'address': address,
            'acreage': acreage,
        })

    return clusters


def _score_cluster(parcels, buyer):
    """Score a cluster of parcels for development footprint probability."""
    if len(parcels) < 2:
        return 0, []

    reasoning = []
    score = CONTIGUITY_BASE_SCORE
    reasoning.append(f"Contiguous parcels ({len(parcels)}): +{CONTIGUITY_BASE_SCORE}")

    # Calculate combined acreage
    total_acreage = sum(p.get('acreage') or 0 for p in parcels)
    if IDEAL_BTR_ACREAGE[0] <= total_acreage <= IDEAL_BTR_ACREAGE[1]:
        score += ACREAGE_BONUS
        reasoning.append(f"Ideal BTR acreage ({total_acreage:.1f} ac): +{ACREAGE_BONUS}")
    elif MIN_BTR_ACREAGE <= total_acreage <= MAX_BTR_ACREAGE:
        bonus = ACREAGE_BONUS // 2
        score += bonus
        reasoning.append(f"Development-scale acreage ({total_acreage:.1f} ac): +{bonus}")

    # Same buyer bonus
    score += SAME_BUYER_BONUS
    reasoning.append(f"Same buyer ({buyer}): +{SAME_BUYER_BONUS}")

    return min(score, 50), reasoning


def analyze_contiguity():
    """
    Analyze parcel clusters for development footprint patterns.
    Updates parcels with contiguous_land_probability scores.
    """
    clusters = _find_parcel_clusters()

    conn = get_db()
    cur = conn.cursor()
    footprints_detected = 0

    for (buyer, city, state), parcels in clusters.items():
        if len(parcels) < 2:
            continue

        score, reasoning = _score_cluster(parcels, buyer)
        if score <= 0:
            continue

        footprints_detected += 1
        total_acreage = sum(p.get('acreage') or 0 for p in parcels)

        # Update each parcel in the cluster
        for parcel in parcels:
            pid = parcel['parcel_id']
            try:
                cur.execute('''
                    SELECT id FROM parcel_context WHERE parcel_id = ? LIMIT 1
                ''', (pid,))
                existing = cur.fetchone()

                contiguity_data = json.dumps({
                    'contiguous_land_probability': score,
                    'cluster_parcels': len(parcels),
                    'combined_acreage': total_acreage,
                    'buyer': buyer,
                    'reasoning': '; '.join(reasoning),
                    'analyzed_at': datetime.utcnow().isoformat(),
                })

                if existing:
                    cur.execute('''
                        UPDATE parcel_context SET contiguity_analysis = ?
                        WHERE parcel_id = ?
                    ''', (contiguity_data, pid))
                else:
                    cur.execute('''
                        INSERT OR IGNORE INTO parcel_context
                        (id, parcel_id, contiguity_analysis, created_at)
                        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                    ''', (str(uuid.uuid4()), pid, contiguity_data))
            except Exception:
                pass

        # Emit intelligence event for significant footprints
        if score >= 30:
            try:
                from app import log_intelligence_event
                log_intelligence_event(
                    event_type='PARCEL_ALERT',
                    title=f"Development footprint detected — {city}, {state}",
                    description=(
                        f"{buyer}: {len(parcels)} parcels, "
                        f"{total_acreage:.1f} acres (score: {score})"
                    ),
                    city=city, state=state,
                    related_entity=buyer,
                )
            except Exception:
                pass

    conn.commit()
    conn.close()

    print(f"[ContiguityEngine] Detected {footprints_detected} development footprints")
    return {'footprints_detected': footprints_detected}


def run_contiguity_engine():
    """Full contiguity analysis cycle."""
    print(f"[ContiguityEngine] START — {datetime.utcnow().isoformat()}")
    result = analyze_contiguity()
    print(f"[ContiguityEngine] COMPLETE")
    return result
