"""
Builder Expansion Pattern Detection Engine.
Detects builders preparing multiple developments across regions
by tracking permit filings grouped by builder.

If a builder files permits across multiple parcels within a short window,
generates a BUILDER_EXPANSION_PATTERN signal.
"""
import json
import uuid
from collections import defaultdict
from datetime import datetime, timedelta

from db import get_db


# Thresholds for pattern detection
MIN_PERMITS_FOR_PATTERN = 3
WINDOW_DAYS = 90
PROBABILITY_BOOST = 10


def _detect_builder_patterns():
    """
    Scan property_signals for builders filing permits across multiple
    parcels/locations within a short time window.
    """
    conn = get_db()
    cur = conn.cursor()

    cutoff = (datetime.utcnow() - timedelta(days=WINDOW_DAYS)).isoformat()

    # Get permit-type signals grouped by entity/builder
    cur.execute('''
        SELECT entity_name, signal_type, city, state, parcel_id,
               address, metadata, created_at
        FROM property_signals
        WHERE entity_name IS NOT NULL AND entity_name != ''
        AND signal_type IN (
            'BUILDING_PERMIT', 'MULTIFAMILY_PERMIT', 'SUBDIVISION_PERMIT',
            'SITE_DEVELOPMENT_PERMIT', 'RESIDENTIAL_COMPLEX_PERMIT',
            'SITE_PLAN_SUBMISSION', 'GRADING_PLAN', 'ENGINEERING_REVIEW'
        )
        AND created_at >= ?
        ORDER BY entity_name, created_at
    ''', (cutoff,))

    rows = cur.fetchall()
    conn.close()

    # Group by builder
    builder_permits = defaultdict(list)
    for entity_name, signal_type, city, state, parcel_id, address, metadata, created_at in rows:
        normalized = entity_name.upper().strip()
        builder_permits[normalized].append({
            'entity_name': entity_name,
            'signal_type': signal_type,
            'city': city,
            'state': state,
            'parcel_id': parcel_id,
            'address': address,
            'created_at': created_at,
        })

    # Detect patterns: builders with permits across multiple locations
    patterns = []
    for builder_key, permits in builder_permits.items():
        if len(permits) < MIN_PERMITS_FOR_PATTERN:
            continue

        # Count distinct locations (city+state combos or parcel IDs)
        locations = set()
        for p in permits:
            if p['parcel_id']:
                locations.add(p['parcel_id'])
            elif p['address']:
                locations.add(f"{p['address']}|{p['city']}|{p['state']}")
            else:
                locations.add(f"{p['city']}|{p['state']}")

        if len(locations) >= 2:
            # Group by region (city, state)
            regions = defaultdict(int)
            for p in permits:
                region_key = f"{p['city']}, {p['state']}"
                regions[region_key] += 1

            patterns.append({
                'builder_name': permits[0]['entity_name'],
                'builder_key': builder_key,
                'permit_count': len(permits),
                'location_count': len(locations),
                'regions': dict(regions),
                'signal_date': datetime.utcnow().isoformat(),
            })

    return patterns


def _store_builder_patterns(patterns):
    """Store builder expansion pattern signals."""
    conn = get_db()
    cur = conn.cursor()
    stored = 0

    for pattern in patterns:
        sig_id = str(uuid.uuid4())
        metadata = {
            'source_collector': 'builder_pattern_engine',
            'builder_name': pattern['builder_name'],
            'permit_count': pattern['permit_count'],
            'location_count': pattern['location_count'],
            'regions': pattern['regions'],
        }

        # Pick the primary region (most permits)
        primary_region = max(pattern['regions'].items(), key=lambda x: x[1])
        region_parts = primary_region[0].split(', ')
        city = region_parts[0] if len(region_parts) > 0 else None
        state = region_parts[1] if len(region_parts) > 1 else None

        try:
            cur.execute('''
                INSERT OR IGNORE INTO property_signals
                (id, signal_type, source, entity_name,
                 city, state, metadata, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                sig_id, 'BUILDER_EXPANSION_PATTERN', 'builder_pattern_engine',
                pattern['builder_name'], city, state,
                json.dumps(metadata, default=str),
            ))
            stored += 1
        except Exception:
            pass

    conn.commit()
    conn.close()
    return stored


def _boost_nearby_parcels(patterns):
    """Boost development probability for parcels near builder expansion patterns."""
    conn = get_db()
    cur = conn.cursor()
    boosted = 0

    for pattern in patterns:
        for region_str, count in pattern['regions'].items():
            region_parts = region_str.split(', ')
            city = region_parts[0] if len(region_parts) > 0 else None
            state = region_parts[1] if len(region_parts) > 1 else None
            if not city or not state:
                continue
            try:
                cur.execute('''
                    UPDATE parcels SET development_probability = MIN(
                        COALESCE(development_probability, 0) + ?, 100
                    ) WHERE city = ? AND state = ? AND parcel_id IS NOT NULL
                ''', (PROBABILITY_BOOST, city, state))
                boosted += cur.rowcount
            except Exception as e:
                print(f"[BuilderPatternEngine] Boost error: {e}")

    conn.commit()
    conn.close()
    return boosted


def run_builder_pattern_detection():
    """Main entry point: detect builder expansion patterns."""
    print(f"[BuilderPatternEngine] START — {datetime.utcnow().isoformat()}")

    patterns = _detect_builder_patterns()
    print(f"[BuilderPatternEngine] Detected {len(patterns)} builder expansion patterns")

    if patterns:
        stored = _store_builder_patterns(patterns)
        print(f"[BuilderPatternEngine] Stored {stored} pattern signals")

        boosted = _boost_nearby_parcels(patterns)
        print(f"[BuilderPatternEngine] Boosted {boosted} nearby parcels")

        for p in patterns:
            print(f"  Builder: {p['builder_name']} — {p['permit_count']} permits across {p['location_count']} locations")
            for region, count in p['regions'].items():
                print(f"    {region}: {count} permits")

        try:
            from app import log_intelligence_event
            log_intelligence_event(
                event_type='BUILDER_EXPANSION_PATTERN',
                title=f"Builder expansion patterns detected",
                description=f"{len(patterns)} builders filing across multiple locations",
            )
        except Exception:
            pass

    print(f"[BuilderPatternEngine] COMPLETE")
    return {'patterns_detected': len(patterns)}
