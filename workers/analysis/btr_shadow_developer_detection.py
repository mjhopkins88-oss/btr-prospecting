"""
BTR Shadow Developer Detection Engine.
Identifies developers quietly assembling land and preparing Build-to-Rent (BTR)
communities before any permits or public announcements appear.

Detects patterns that indicate early-stage BTR development activity:
  - LLC formations with residential naming patterns
  - Land purchases and parcel assemblage
  - Shared registered agents across entities
  - Civil engineering engagement
  - Subdivision plat filings
  - Contractor/builder relationships
  - Zoning classification signals
  - Infrastructure planning indicators

When high-probability BTR developer activity is detected, generates a
BTR_SHADOW_DEVELOPER_DETECTED intelligence event.
"""
import json
import math
import uuid
from collections import defaultdict
from datetime import datetime, timedelta

from db import get_db


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# LLC naming patterns associated with residential development
BTR_NAME_KEYWORDS = [
    'homes', 'residential', 'communities', 'living', 'holdings',
    'development', 'properties', 'village', 'estates', 'quarters',
    'rentals', 'apartments', 'dwelling', 'habitat', 'realty',
    'housing', 'manor', 'villas', 'townhomes', 'cottages',
]

# Lookback window for entity formation scanning
ENTITY_LOOKBACK_DAYS = 365

# Land cluster detection thresholds
CLUSTER_RADIUS_MILES_MIN = 0.5
CLUSTER_RADIUS_MILES_MAX = 2.0
CLUSTER_ACREAGE_MIN = 10
CLUSTER_ACREAGE_MAX = 80

# Approx miles per degree at mid-latitudes
MILES_PER_DEG_LAT = 69.0
MILES_PER_DEG_LON = 54.6  # ~at 38°N

# BTR signal scoring
BTR_SCORES = {
    'land_cluster_detected': 25,
    'subdivision_plat_filing': 30,
    'engineering_firm_engagement': 20,
    'builder_relationship_detected': 20,
    'zoning_residential_high_density': 10,
    'shared_registered_agent': 15,
    'multiple_llcs_same_agent': 15,
    'no_home_sale_listings': 10,
    'developer_btr_history': 25,
    'infrastructure_signal': 15,
}

BTR_THRESHOLD = 60

# Probability boost when shadow developer overlaps with other signals
CONVERGENCE_BOOST = 20


# ---------------------------------------------------------------------------
# Step 0: Ensure tables exist
# ---------------------------------------------------------------------------

def _ensure_tables():
    """Create required tables if they don't exist."""
    conn = get_db()
    cur = conn.cursor()

    cur.execute('''
        CREATE TABLE IF NOT EXISTS shadow_developer_entities (
            id TEXT PRIMARY KEY,
            entity_name TEXT NOT NULL,
            state TEXT,
            formation_date TEXT,
            registered_agent TEXT,
            confidence_score REAL DEFAULT 0,
            possible_btr_indicator TEXT,
            first_detected_at TEXT DEFAULT CURRENT_TIMESTAMP,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS developer_land_clusters (
            id TEXT PRIMARY KEY,
            entity_name TEXT NOT NULL,
            parcel_ids TEXT,
            total_acreage REAL DEFAULT 0,
            purchase_count INTEGER DEFAULT 0,
            cluster_center_lat REAL,
            cluster_center_lon REAL,
            first_purchase_date TEXT,
            last_purchase_date TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS btr_shadow_development_signals (
            id TEXT PRIMARY KEY,
            entity_name TEXT NOT NULL,
            associated_parcels TEXT,
            acreage REAL DEFAULT 0,
            signal_score REAL DEFAULT 0,
            btr_probability REAL DEFAULT 0,
            cluster_center_lat REAL,
            cluster_center_lon REAL,
            first_signal_detected TEXT,
            last_signal_detected TEXT,
            signal_details TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Step 1: Detect Developer Entity Clusters
# ---------------------------------------------------------------------------

def _detect_developer_entities():
    """
    Scan entity filings and property signals for new LLCs created within the
    past 12 months whose names match residential development patterns.
    """
    conn = get_db()
    cur = conn.cursor()

    cutoff = (datetime.utcnow() - timedelta(days=ENTITY_LOOKBACK_DAYS)).isoformat()

    # Pull entity-related signals (LLC formations, deed transfers, etc.)
    cur.execute('''
        SELECT DISTINCT entity_name, state, metadata, created_at
        FROM property_signals
        WHERE entity_name IS NOT NULL AND entity_name != ''
        AND signal_type IN (
            'LLC_FORMATION', 'DEED_TRANSFER', 'OWNER_CHANGE',
            'LAND_PURCHASE', 'ENTITY_FILING'
        )
        AND created_at >= ?
        ORDER BY created_at DESC
    ''', (cutoff,))
    rows = cur.fetchall()

    entities = {}
    for entity_name, state, metadata_str, created_at in rows:
        name_upper = entity_name.upper().strip()

        # Check for BTR-related naming patterns
        indicators = []
        for keyword in BTR_NAME_KEYWORDS:
            if keyword.upper() in name_upper:
                indicators.append(keyword)

        # Check for LLC/entity patterns
        is_llc = any(tag in name_upper for tag in ['LLC', 'L.L.C.', 'LP', 'L.P.', 'INC', 'CORP'])

        if not indicators and not is_llc:
            continue

        # Extract registered agent from metadata if available
        registered_agent = None
        if metadata_str:
            try:
                meta = json.loads(metadata_str) if isinstance(metadata_str, str) else metadata_str
                registered_agent = (
                    meta.get('registered_agent') or
                    meta.get('agent') or
                    meta.get('statutory_agent') or
                    ''
                ).strip() or None
            except (json.JSONDecodeError, TypeError):
                pass

        # Confidence based on how many indicators match
        confidence = min(30 + len(indicators) * 15, 80)
        if is_llc and indicators:
            confidence = min(confidence + 10, 90)

        btr_indicator = ', '.join(indicators) if indicators else 'llc_entity'

        key = name_upper
        if key not in entities or confidence > entities[key]['confidence_score']:
            entities[key] = {
                'entity_name': entity_name,
                'state': state,
                'formation_date': created_at,
                'registered_agent': registered_agent,
                'confidence_score': confidence,
                'possible_btr_indicator': btr_indicator,
            }

    conn.close()
    return list(entities.values())


def _store_developer_entities(entities):
    """Store detected developer entities in shadow_developer_entities table."""
    conn = get_db()
    cur = conn.cursor()
    stored = 0

    for ent in entities:
        try:
            cur.execute('''
                INSERT OR IGNORE INTO shadow_developer_entities
                (id, entity_name, state, formation_date, registered_agent,
                 confidence_score, possible_btr_indicator, first_detected_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                str(uuid.uuid4()),
                ent['entity_name'],
                ent['state'],
                ent['formation_date'],
                ent['registered_agent'],
                ent['confidence_score'],
                ent['possible_btr_indicator'],
            ))
            stored += 1
        except Exception:
            pass

    conn.commit()
    conn.close()
    return stored


# ---------------------------------------------------------------------------
# Step 2: Land Acquisition Pattern Detection
# ---------------------------------------------------------------------------

def _detect_land_clusters(entities):
    """
    Track land purchases connected to detected entities.
    Identify clusters of multiple parcels within 0.5-2 mile radius,
    10-80 acres total, near suburban growth corridors.
    """
    conn = get_db()
    cur = conn.cursor()

    entity_names = [e['entity_name'] for e in entities]
    if not entity_names:
        conn.close()
        return []

    clusters = []

    for entity_name in entity_names:
        # Get land-related signals for this entity
        cur.execute('''
            SELECT parcel_id, address, city, state, latitude, longitude,
                   metadata, created_at
            FROM property_signals
            WHERE entity_name = ?
            AND signal_type IN ('LAND_PURCHASE', 'DEED_TRANSFER', 'OWNER_CHANGE')
            AND parcel_id IS NOT NULL
            ORDER BY created_at
        ''', (entity_name,))
        parcels = cur.fetchall()

        if len(parcels) < 2:
            continue

        # Extract parcel coordinates and info
        parcel_data = []
        for row in parcels:
            parcel_id, address, city, state, lat, lon, meta_str, created_at = row
            acreage = 0
            if meta_str:
                try:
                    meta = json.loads(meta_str) if isinstance(meta_str, str) else meta_str
                    acreage = float(meta.get('acreage', 0) or meta.get('lot_size_acres', 0) or 0)
                except (json.JSONDecodeError, TypeError, ValueError):
                    pass

            parcel_data.append({
                'parcel_id': parcel_id,
                'lat': float(lat) if lat else None,
                'lon': float(lon) if lon else None,
                'acreage': acreage,
                'city': city,
                'state': state,
                'created_at': created_at,
            })

        # Find geographic clusters using simple distance-based grouping
        geo_parcels = [p for p in parcel_data if p['lat'] and p['lon']]

        if len(geo_parcels) >= 2:
            cluster = _find_parcel_cluster(geo_parcels)
            if cluster:
                cluster['entity_name'] = entity_name
                clusters.append(cluster)
        elif len(parcel_data) >= 2:
            # No geo data — still track as a cluster by entity
            total_acreage = sum(p['acreage'] for p in parcel_data)
            dates = [p['created_at'] for p in parcel_data if p['created_at']]
            clusters.append({
                'entity_name': entity_name,
                'parcel_ids': [p['parcel_id'] for p in parcel_data],
                'total_acreage': total_acreage,
                'purchase_count': len(parcel_data),
                'cluster_center_lat': None,
                'cluster_center_lon': None,
                'first_purchase_date': min(dates) if dates else None,
                'last_purchase_date': max(dates) if dates else None,
            })

    conn.close()
    return clusters


def _find_parcel_cluster(parcels):
    """
    Find the tightest cluster of parcels within the radius threshold.
    Returns cluster info if parcels are within 0.5-2 mile radius.
    """
    if not parcels:
        return None

    # Calculate centroid
    avg_lat = sum(p['lat'] for p in parcels) / len(parcels)
    avg_lon = sum(p['lon'] for p in parcels) / len(parcels)

    # Check if all parcels are within max radius of centroid
    max_dist = 0
    for p in parcels:
        dist = _haversine_miles(avg_lat, avg_lon, p['lat'], p['lon'])
        max_dist = max(max_dist, dist)

    if max_dist > CLUSTER_RADIUS_MILES_MAX:
        return None

    total_acreage = sum(p['acreage'] for p in parcels)
    parcel_ids = [p['parcel_id'] for p in parcels]
    dates = [p['created_at'] for p in parcels if p['created_at']]

    return {
        'parcel_ids': parcel_ids,
        'total_acreage': total_acreage,
        'purchase_count': len(parcels),
        'cluster_center_lat': avg_lat,
        'cluster_center_lon': avg_lon,
        'first_purchase_date': min(dates) if dates else None,
        'last_purchase_date': max(dates) if dates else None,
    }


def _haversine_miles(lat1, lon1, lat2, lon2):
    """Calculate distance between two points in miles using Haversine formula."""
    R = 3959  # Earth radius in miles
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (math.sin(dlat / 2) ** 2 +
         math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *
         math.sin(dlon / 2) ** 2)
    c = 2 * math.asin(math.sqrt(a))
    return R * c


def _store_land_clusters(clusters):
    """Store detected land clusters in developer_land_clusters table."""
    conn = get_db()
    cur = conn.cursor()
    stored = 0

    for cluster in clusters:
        try:
            cur.execute('''
                INSERT OR IGNORE INTO developer_land_clusters
                (id, entity_name, parcel_ids, total_acreage, purchase_count,
                 cluster_center_lat, cluster_center_lon,
                 first_purchase_date, last_purchase_date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                str(uuid.uuid4()),
                cluster['entity_name'],
                json.dumps(cluster['parcel_ids']),
                cluster['total_acreage'],
                cluster['purchase_count'],
                cluster['cluster_center_lat'],
                cluster['cluster_center_lon'],
                cluster['first_purchase_date'],
                cluster['last_purchase_date'],
            ))
            stored += 1
        except Exception:
            pass

    conn.commit()
    conn.close()
    return stored


# ---------------------------------------------------------------------------
# Step 3: BTR Pattern Identification & Scoring
# ---------------------------------------------------------------------------

def _calculate_btr_score(entity_name, cluster):
    """
    Calculate BTR probability score for an entity/cluster combination.

    Scoring:
      land cluster detected         → +25
      subdivision plat filing       → +30
      engineering firm engagement   → +20
      builder relationship detected → +20
      zoning residential high dens  → +10
      shared registered agent       → +15
      multiple LLCs same agent      → +15
      no home sale listings         → +10
      developer BTR history         → +25
      infrastructure signal         → +15
    """
    conn = get_db()
    cur = conn.cursor()
    score = 0
    details = []

    # Signal 1: Land cluster detected
    if cluster and cluster['purchase_count'] >= 2:
        score += BTR_SCORES['land_cluster_detected']
        details.append(f"land_cluster: {cluster['purchase_count']} parcels, {cluster['total_acreage']:.1f} acres")

    # Signal 2: Subdivision plat filings
    cur.execute('''
        SELECT COUNT(*) FROM property_signals
        WHERE entity_name = ?
        AND signal_type IN ('SUBDIVISION_PLAT', 'PRELIMINARY_PLAT', 'FINAL_PLAT',
                            'SUBDIVISION_APPLICATION', 'SUBDIVISION_PERMIT', 'LOT_SPLIT')
    ''', (entity_name,))
    plat_count = cur.fetchone()[0]
    if plat_count > 0:
        score += BTR_SCORES['subdivision_plat_filing']
        details.append(f"subdivision_plat: {plat_count} filings")

    # Signal 3: Engineering firm engagement
    cur.execute('''
        SELECT COUNT(*) FROM property_signals
        WHERE entity_name = ?
        AND signal_type IN ('CIVIL_ENGINEERING_PLAN', 'ENGINEERING_REVIEW',
                            'GRADING_PLAN', 'DRAINAGE_REPORT',
                            'ENGINEERING_PLAN_SUBMISSION', 'SITE_PLAN_SUBMISSION')
    ''', (entity_name,))
    eng_count = cur.fetchone()[0]
    if eng_count > 0:
        score += BTR_SCORES['engineering_firm_engagement']
        details.append(f"engineering_engagement: {eng_count} signals")

    # Signal 4: Builder relationship detected
    cur.execute('''
        SELECT COUNT(*) FROM developer_network_edges
        WHERE (entity_a = ? OR entity_b = ?)
        AND relationship_type IN ('DEVELOPER_CONTRACTOR', 'CONTRACTOR_ENGINEER')
        AND relationship_strength >= 30
    ''', (entity_name, entity_name))
    builder_rels = cur.fetchone()[0]
    if builder_rels > 0:
        score += BTR_SCORES['builder_relationship_detected']
        details.append(f"builder_relationships: {builder_rels}")

    # Signal 5: Zoning — residential high density
    cur.execute('''
        SELECT COUNT(*) FROM property_signals
        WHERE entity_name = ?
        AND signal_type IN ('REZONING_REQUEST', 'ZONING_AGENDA_ITEM',
                            'ZONING_APPLICATION')
        AND (metadata LIKE '%residential%' OR metadata LIKE '%multifamily%'
             OR metadata LIKE '%high density%' OR metadata LIKE '%R-3%'
             OR metadata LIKE '%R-4%' OR metadata LIKE '%PUD%')
    ''', (entity_name,))
    zoning_count = cur.fetchone()[0]
    if zoning_count > 0:
        score += BTR_SCORES['zoning_residential_high_density']
        details.append(f"residential_zoning: {zoning_count} signals")

    # Signal 6: Shared registered agent across multiple entities
    cur.execute('''
        SELECT registered_agent, COUNT(*) as cnt
        FROM shadow_developer_entities
        WHERE registered_agent IS NOT NULL AND registered_agent != ''
        GROUP BY registered_agent
        HAVING COUNT(*) >= 2
    ''')
    shared_agents = cur.fetchall()
    # Check if this entity's agent is in the shared list
    cur.execute('''
        SELECT registered_agent FROM shadow_developer_entities
        WHERE entity_name = ?
    ''', (entity_name,))
    ent_agent_row = cur.fetchone()
    if ent_agent_row and ent_agent_row[0]:
        for agent, cnt in shared_agents:
            if agent == ent_agent_row[0]:
                score += BTR_SCORES['shared_registered_agent']
                score += BTR_SCORES['multiple_llcs_same_agent']
                details.append(f"shared_agent: {agent} ({cnt} entities)")
                break

    # Signal 7: Infrastructure planning signals nearby
    if cluster and cluster.get('cluster_center_lat') and cluster.get('cluster_center_lon'):
        lat, lon = cluster['cluster_center_lat'], cluster['cluster_center_lon']
        lat_range = CLUSTER_RADIUS_MILES_MAX / MILES_PER_DEG_LAT
        lon_range = CLUSTER_RADIUS_MILES_MAX / MILES_PER_DEG_LON
        cur.execute('''
            SELECT COUNT(*) FROM property_signals
            WHERE signal_type IN ('TRAFFIC_IMPACT_STUDY', 'ROAD_EXPANSION_APPROVAL',
                                  'UTILITY_CAPACITY_EXPANSION', 'INFRASTRUCTURE_BID',
                                  'UTILITY_CONNECTION_REQUEST', 'NEW_SERVICE_APPLICATION')
            AND latitude BETWEEN ? AND ?
            AND longitude BETWEEN ? AND ?
        ''', (lat - lat_range, lat + lat_range, lon - lon_range, lon + lon_range))
        infra_count = cur.fetchone()[0]
        if infra_count > 0:
            score += BTR_SCORES['infrastructure_signal']
            details.append(f"infrastructure_signals: {infra_count}")

    # Signal 8: Developer has BTR history (check for prior BTR signals or keywords)
    cur.execute('''
        SELECT COUNT(*) FROM property_signals
        WHERE entity_name = ?
        AND (metadata LIKE '%build-to-rent%' OR metadata LIKE '%build to rent%'
             OR metadata LIKE '%BTR%' OR metadata LIKE '%rental community%'
             OR metadata LIKE '%single-family rental%')
    ''', (entity_name,))
    btr_history = cur.fetchone()[0]
    if btr_history > 0:
        score += BTR_SCORES['developer_btr_history']
        details.append(f"btr_history: {btr_history} mentions")

    conn.close()

    btr_probability = min(score, 100)
    return score, btr_probability, details


# ---------------------------------------------------------------------------
# Step 4: Developer Relationship Analysis
# ---------------------------------------------------------------------------

def _check_developer_relationships(entity_name):
    """
    Cross-reference detected developer with existing network intelligence.
    Returns confidence boost based on relationships with known BTR-associated
    contractors, engineers, builders, lenders, and suppliers.
    """
    conn = get_db()
    cur = conn.cursor()
    boost = 0
    relationships = []

    # Check developer network edges for strong relationships
    cur.execute('''
        SELECT entity_a, entity_b, relationship_type, relationship_strength
        FROM developer_network_edges
        WHERE (entity_a = ? OR entity_b = ?)
        AND relationship_strength >= 40
        ORDER BY relationship_strength DESC
    ''', (entity_name, entity_name))
    edges = cur.fetchall()

    for entity_a, entity_b, rel_type, strength in edges:
        partner = entity_b if entity_a == entity_name else entity_a

        # Check if partner is a known BTR-associated entity
        cur.execute('''
            SELECT COUNT(*) FROM btr_shadow_development_signals
            WHERE entity_name = ? AND btr_probability >= 50
        ''', (partner,))
        is_btr_associated = cur.fetchone()[0] > 0

        if is_btr_associated:
            boost += 15
            relationships.append(f"btr_partner: {partner} (strength={strength})")
        elif strength >= 60:
            boost += 5
            relationships.append(f"strong_partner: {partner} ({rel_type}, strength={strength})")

    # Check contractor-developer relationships table
    cur.execute('''
        SELECT cf.firm_name, cdr.project_count
        FROM contractor_developer_relationships cdr
        JOIN contractor_firms cf ON cf.id = cdr.contractor_id
        WHERE cdr.developer_id = ?
        AND cdr.project_count >= 2
    ''', (entity_name,))
    contractor_rows = cur.fetchall()
    for firm_name, project_count in contractor_rows:
        boost += min(10, project_count * 3)
        relationships.append(f"contractor: {firm_name} ({project_count} projects)")

    conn.close()
    return min(boost, 30), relationships


# ---------------------------------------------------------------------------
# Step 5: Generate Intelligence Event
# ---------------------------------------------------------------------------

def _store_btr_signals(signals):
    """Store BTR shadow development signals and generate intelligence events."""
    conn = get_db()
    cur = conn.cursor()
    stored = 0

    for sig in signals:
        sig_id = str(uuid.uuid4())
        try:
            cur.execute('''
                INSERT OR IGNORE INTO btr_shadow_development_signals
                (id, entity_name, associated_parcels, acreage, signal_score,
                 btr_probability, cluster_center_lat, cluster_center_lon,
                 first_signal_detected, last_signal_detected, signal_details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                sig_id,
                sig['entity_name'],
                json.dumps(sig.get('associated_parcels', [])),
                sig.get('acreage', 0),
                sig['signal_score'],
                sig['btr_probability'],
                sig.get('cluster_center_lat'),
                sig.get('cluster_center_lon'),
                sig.get('first_signal_detected'),
                sig.get('last_signal_detected'),
                json.dumps(sig.get('signal_details', []), default=str),
            ))
            stored += 1
        except Exception:
            pass

        # Also store as a property signal for cross-engine visibility
        try:
            cur.execute('''
                INSERT OR IGNORE INTO property_signals
                (id, signal_type, source, entity_name, city, state,
                 latitude, longitude, metadata, created_at)
                VALUES (?, 'BTR_SHADOW_DEVELOPER_DETECTED', 'btr_shadow_detection',
                        ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                str(uuid.uuid4()),
                sig['entity_name'],
                sig.get('city'),
                sig.get('state'),
                sig.get('cluster_center_lat'),
                sig.get('cluster_center_lon'),
                json.dumps({
                    'source_collector': 'btr_shadow_developer_detection',
                    'signal_score': sig['signal_score'],
                    'btr_probability': sig['btr_probability'],
                    'acreage': sig.get('acreage', 0),
                    'parcel_count': len(sig.get('associated_parcels', [])),
                    'signal_details': sig.get('signal_details', []),
                }, default=str),
            ))
        except Exception:
            pass

    conn.commit()
    conn.close()
    return stored


def _emit_intelligence_events(signals):
    """Generate BTR_SHADOW_DEVELOPER_DETECTED intelligence events."""
    for sig in signals:
        try:
            from app import log_intelligence_event
            log_intelligence_event(
                event_type='BTR_SHADOW_DEVELOPER_DETECTED',
                title=f"BTR Developer Activity Detected: {sig['entity_name']}",
                description=(
                    f"Shadow developer detected with BTR probability {sig['btr_probability']}%. "
                    f"Score: {sig['signal_score']}. "
                    f"Parcels: {len(sig.get('associated_parcels', []))}. "
                    f"Acreage: {sig.get('acreage', 0):.1f}. "
                    f"Signals: {', '.join(sig.get('signal_details', [])[:3])}"
                ),
                city=sig.get('city'),
                state=sig.get('state'),
                related_entity=sig['entity_name'],
            )
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Step 6: Integration With Development Prediction
# ---------------------------------------------------------------------------

def _boost_development_probability(signals):
    """
    When a shadow developer cluster overlaps with additional signals
    (zoning requests, engineering plans, contractor signals, planning agenda
    mentions, infrastructure extensions), increase development_probability.
    """
    conn = get_db()
    cur = conn.cursor()
    boosted = 0

    for sig in signals:
        parcel_ids = sig.get('associated_parcels', [])
        if not parcel_ids:
            continue

        for parcel_id in parcel_ids:
            # Check for convergent signals on this parcel
            cur.execute('''
                SELECT COUNT(DISTINCT signal_type) FROM property_signals
                WHERE parcel_id = ?
                AND signal_type IN (
                    'REZONING_REQUEST', 'ZONING_AGENDA_ITEM', 'ZONING_APPLICATION',
                    'CIVIL_ENGINEERING_PLAN', 'ENGINEERING_REVIEW', 'GRADING_PLAN',
                    'CONTRACTOR_BID', 'SITE_GRADING', 'SURVEY_WORK',
                    'DEVELOPMENT_REVIEW_CASE', 'SITE_PLAN_SUBMISSION',
                    'TRAFFIC_IMPACT_STUDY', 'ROAD_EXPANSION_APPROVAL',
                    'UTILITY_CAPACITY_EXPANSION', 'UTILITY_CONNECTION_REQUEST'
                )
            ''', (parcel_id,))
            convergent_count = cur.fetchone()[0]

            if convergent_count > 0:
                # More convergent signals → bigger boost
                boost = min(CONVERGENCE_BOOST + (convergent_count * 5), 40)
                try:
                    cur.execute('''
                        UPDATE parcels
                        SET development_probability = MIN(99,
                            COALESCE(development_probability, 0) + ?)
                        WHERE parcel_id = ?
                    ''', (boost, parcel_id))
                    if cur.rowcount > 0:
                        boosted += 1
                except Exception:
                    pass

    conn.commit()
    conn.close()
    return boosted


# ---------------------------------------------------------------------------
# Step 7: Main entry point
# ---------------------------------------------------------------------------

def run_btr_shadow_developer_detection():
    """
    Main entry point — detect shadow developers assembling BTR communities.

    Shadow developer detections appear in:
      - Development Radar Map
      - Developer Intelligence Profiles
      - Opportunity Feed

    Signals appear as "BTR Developer Activity Detected" before any permits
    or planning approvals appear.
    """
    print(f"[BTRShadowDetection] START — {datetime.utcnow().isoformat()}")

    # Step 0: Ensure tables exist
    _ensure_tables()

    # Step 1: Detect developer entity clusters
    entities = _detect_developer_entities()
    print(f"[BTRShadowDetection] Detected {len(entities)} potential developer entities")

    if entities:
        stored_entities = _store_developer_entities(entities)
        print(f"[BTRShadowDetection] Stored {stored_entities} developer entities")

    # Step 2: Land acquisition pattern detection
    clusters = _detect_land_clusters(entities)
    print(f"[BTRShadowDetection] Found {len(clusters)} land acquisition clusters")

    if clusters:
        stored_clusters = _store_land_clusters(clusters)
        print(f"[BTRShadowDetection] Stored {stored_clusters} land clusters")

    # Steps 3-5: BTR scoring, relationship analysis, and signal generation
    btr_signals = []
    cluster_map = {c['entity_name']: c for c in clusters}

    for entity in entities:
        entity_name = entity['entity_name']
        cluster = cluster_map.get(entity_name)

        # Step 3: Calculate BTR score
        score, btr_probability, details = _calculate_btr_score(entity_name, cluster)

        # Step 4: Developer relationship analysis
        rel_boost, rel_details = _check_developer_relationships(entity_name)
        score += rel_boost
        btr_probability = min(score, 100)
        details.extend(rel_details)

        if score >= BTR_THRESHOLD:
            signal = {
                'entity_name': entity_name,
                'associated_parcels': cluster['parcel_ids'] if cluster else [],
                'acreage': cluster['total_acreage'] if cluster else 0,
                'signal_score': score,
                'btr_probability': btr_probability,
                'cluster_center_lat': cluster['cluster_center_lat'] if cluster else None,
                'cluster_center_lon': cluster['cluster_center_lon'] if cluster else None,
                'first_signal_detected': cluster['first_purchase_date'] if cluster else entity['formation_date'],
                'last_signal_detected': cluster['last_purchase_date'] if cluster else entity['formation_date'],
                'signal_details': details,
                'city': entity.get('city'),
                'state': entity.get('state'),
            }
            btr_signals.append(signal)

    print(f"[BTRShadowDetection] {len(btr_signals)} entities exceed BTR threshold (score >= {BTR_THRESHOLD})")

    if btr_signals:
        # Step 5: Store signals and generate intelligence events
        stored_signals = _store_btr_signals(btr_signals)
        print(f"[BTRShadowDetection] Stored {stored_signals} BTR shadow development signals")

        _emit_intelligence_events(btr_signals)
        print(f"[BTRShadowDetection] Emitted {len(btr_signals)} intelligence events")

        # Step 6: Boost development probability for convergent parcels
        boosted = _boost_development_probability(btr_signals)
        print(f"[BTRShadowDetection] Boosted probability for {boosted} parcels")

        # Step 7: Output summary
        for sig in btr_signals:
            print(f"  BTR Developer: {sig['entity_name']}")
            print(f"    Score: {sig['signal_score']} | Probability: {sig['btr_probability']}%")
            print(f"    Parcels: {len(sig['associated_parcels'])} | Acreage: {sig['acreage']:.1f}")
            for detail in sig['signal_details'][:5]:
                print(f"    → {detail}")

    print(f"[BTRShadowDetection] COMPLETE")
    return {
        'entities_detected': len(entities),
        'land_clusters': len(clusters),
        'btr_signals': len(btr_signals),
    }


if __name__ == '__main__':
    run_btr_shadow_developer_detection()
