"""
Parcel First Search Engine

Shifts development intelligence from signal-first detection to parcel-first
discovery. Instead of waiting for development signals to appear in datasets,
this engine proactively scans parcels to identify early indicators of
development preparation — with a strong bias toward Build-to-Rent patterns.

Priority filter (BTR niche):
    10–60 acres, suburban fringe, zoned residential,
    near population growth corridors

Steps:
    1. Parcel Inventory          — build parcel_index for monitored regions
    2. Candidate Filtering       — score & store candidate_parcels
    3. Deep Search               — cross-reference entity/planning/zoning data
    4. Cluster Detection         — group nearby parcels into parcel_clusters
    5. BTR Pattern Bias          — boost parcels matching BTR indicators
    6. Signal Attachment         — link external signals to parcels
    7. Opportunity Generation    — emit DEVELOPMENT_PARCEL_OPPORTUNITY events
    8. Integration               — surface in Radar Map, Feed, Developer Profiles

Tables created / used:
    parcel_index, candidate_parcels, parcel_clusters, parcel_opportunities
"""
import uuid
import json
import math
from datetime import datetime, timedelta

from shared.database import fetch_all, fetch_one, execute, new_id, now_ts


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

LOG_PREFIX = "[ParcelFirstSearch]"

# BTR-niche priority ranges
PRIORITY_ACREAGE_MIN = 10
PRIORITY_ACREAGE_MAX = 60

# Broader candidate floor
CANDIDATE_ACREAGE_MIN = 5

RESIDENTIAL_ZONING_KEYWORDS = {
    "residential", "r-1", "r-2", "r-3", "r-4", "r-5",
    "single-family", "single family", "multifamily", "multi-family",
    "mf", "sf", "pud", "planned unit", "planned_development",
}

MIXED_USE_ZONING_KEYWORDS = {
    "mixed", "mixed-use", "mixed_use", "mu", "flex",
}

SUBURBAN_KEYWORDS = {
    "suburban", "fringe", "unincorporated", "etj",
    "extraterritorial", "growth", "expansion",
}

# Deep-search signal source tables
DEEP_SEARCH_SOURCES = [
    ("entity_filings",        "entity_name",  "Entity Filing"),
    ("engineering_activity",   "company_name", "Engineering Firm"),
    ("planning_agenda_items",  "description",  "Planning Agenda"),
    ("zoning_cases",           "case_type",    "Zoning Request"),
    ("contractor_activity",    "company",      "Contractor Signal"),
    ("utility_signals",        "description",  "Utility Planning"),
    ("land_transactions",      "buyer",        "Nearby Land Purchase"),
]

# Cluster parameters
CLUSTER_RADIUS_MILES = 0.5
CLUSTER_MIN_ACREAGE = 15

# Opportunity threshold
OPPORTUNITY_THRESHOLD = 65
BTR_OPPORTUNITY_THRESHOLD = 55


# ============================================================================
# Step 1 — Parcel Inventory
# ============================================================================

def ensure_parcel_index_table():
    """Create the parcel_index table if it does not exist."""
    execute("""
        CREATE TABLE IF NOT EXISTS parcel_index (
            parcel_id       TEXT PRIMARY KEY,
            owner_entity    TEXT,
            acreage         REAL,
            zoning_type     TEXT,
            last_sale_date  TEXT,
            last_sale_price REAL,
            latitude        REAL,
            longitude       REAL,
            county          TEXT,
            city            TEXT,
            state           TEXT,
            created_at      TEXT,
            updated_at      TEXT
        )
    """)


def ingest_parcel(parcel: dict):
    """
    Upsert a single parcel into parcel_index.
    Expected keys match the table columns.
    """
    pid = parcel.get("parcel_id") or new_id()
    now = now_ts()
    execute(
        """INSERT OR REPLACE INTO parcel_index
           (parcel_id, owner_entity, acreage, zoning_type,
            last_sale_date, last_sale_price,
            latitude, longitude, county, city, state,
            created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        [pid, parcel.get("owner_entity"), parcel.get("acreage"),
         parcel.get("zoning_type"), parcel.get("last_sale_date"),
         parcel.get("last_sale_price"), parcel.get("latitude"),
         parcel.get("longitude"), parcel.get("county"),
         parcel.get("city"), parcel.get("state"), now, now]
    )
    return pid


def build_parcel_index(parcels: list[dict]):
    """Bulk-ingest a list of parcel dicts into parcel_index."""
    ensure_parcel_index_table()
    count = 0
    for p in parcels:
        ingest_parcel(p)
        count += 1
    print(f"{LOG_PREFIX} Indexed {count} parcels.")
    return count


# ============================================================================
# Step 2 — Development Candidate Filtering
# ============================================================================

def ensure_candidate_parcels_table():
    """Create candidate_parcels table if it does not exist."""
    execute("""
        CREATE TABLE IF NOT EXISTS candidate_parcels (
            id                          TEXT PRIMARY KEY,
            parcel_id                   TEXT,
            development_candidate_score INTEGER,
            btr_priority                INTEGER DEFAULT 0,
            score_reasons               TEXT,
            created_at                  TEXT,
            updated_at                  TEXT
        )
    """)


def _zoning_matches(zoning_type, keyword_set):
    """Check if a zoning string contains any keyword from the set."""
    if not zoning_type:
        return False
    z = zoning_type.lower().strip()
    return any(kw in z for kw in keyword_set)


def _is_priority_parcel(parcel):
    """
    Check if a parcel matches the BTR-niche priority filter:
    10–60 acres, suburban fringe, zoned residential, near growth corridors.
    """
    acreage = parcel.get("acreage") or 0
    zoning = (parcel.get("zoning_type") or "").lower()

    in_acreage_range = PRIORITY_ACREAGE_MIN <= acreage <= PRIORITY_ACREAGE_MAX
    is_residential = _zoning_matches(zoning, RESIDENTIAL_ZONING_KEYWORDS)

    return in_acreage_range and is_residential


def score_development_candidate(parcel):
    """
    Score a parcel for development candidacy.

    Priority parcels (10–60 acres, suburban fringe, zoned residential,
    near population growth corridors) receive a significant bonus so they
    are always surfaced first.

    Returns (score, reasons_list, is_btr_priority).
    """
    score = 0
    reasons = []
    acreage = parcel.get("acreage") or 0
    zoning = parcel.get("zoning_type") or ""
    city = parcel.get("city")
    state = parcel.get("state")
    lat = parcel.get("latitude") or 0
    lon = parcel.get("longitude") or 0

    is_priority = _is_priority_parcel(parcel)

    # --- Priority bonus (BTR niche filter) ---
    if is_priority:
        score += 30
        reasons.append("Priority: 10-60 acre residential parcel")

    # --- Acreage ---
    if PRIORITY_ACREAGE_MIN <= acreage <= PRIORITY_ACREAGE_MAX:
        score += 20
        reasons.append(f"Ideal BTR acreage ({acreage:.1f} acres)")
    elif acreage > CANDIDATE_ACREAGE_MIN:
        score += 10
        reasons.append(f"Developable acreage ({acreage:.1f} acres)")

    # --- Zoning ---
    if _zoning_matches(zoning, RESIDENTIAL_ZONING_KEYWORDS):
        score += 15
        reasons.append("Zoned residential")
    elif _zoning_matches(zoning, MIXED_USE_ZONING_KEYWORDS):
        score += 10
        reasons.append("Zoned mixed-use")

    # --- Recent ownership change (last 24 months) ---
    last_sale = parcel.get("last_sale_date")
    if last_sale:
        try:
            sale_dt = datetime.fromisoformat(str(last_sale).replace("Z", ""))
            if (datetime.utcnow() - sale_dt).days <= 730:
                score += 10
                reasons.append("Recent ownership change")
        except Exception:
            pass

    # --- Suburban growth / population corridor proximity ---
    growth_row = fetch_one(
        "SELECT population_growth FROM market_growth_data "
        "WHERE city = ? AND state = ? ORDER BY created_at DESC LIMIT 1",
        [city, state]
    ) if city and state else None

    if growth_row and (growth_row.get("population_growth") or 0) >= 2:
        score += 15
        reasons.append("Near population growth corridor")
        if is_priority:
            score += 10
            reasons.append("Priority: suburban growth corridor match")

    # --- Adjacent to recent development signals ---
    if lat and lon:
        nearby = fetch_one(
            "SELECT COUNT(*) as cnt FROM development_events "
            "WHERE ABS(latitude - ?) < 0.01 AND ABS(longitude - ?) < 0.01 "
            "AND event_date >= ?",
            [lat, lon, (datetime.utcnow() - timedelta(days=365)).isoformat()]
        )
        if nearby and (nearby.get("cnt") or 0) >= 1:
            score += 10
            reasons.append("Adjacent to recent development signals")

    # --- Near infrastructure projects ---
    if lat and lon:
        infra = fetch_one(
            "SELECT COUNT(*) as cnt FROM infrastructure_projects "
            "WHERE ABS(latitude - ?) < 0.02 AND ABS(longitude - ?) < 0.02",
            [lat, lon]
        )
        if infra and (infra.get("cnt") or 0) >= 1:
            score += 10
            reasons.append("Near new infrastructure projects")

    return min(score, 100), reasons, is_priority


def filter_development_candidates(min_score=30):
    """
    Scan parcel_index, score each parcel, and store high-scoring parcels
    in candidate_parcels.  Priority parcels (BTR niche) are always included
    regardless of min_score.
    """
    ensure_candidate_parcels_table()
    parcels = fetch_all("SELECT * FROM parcel_index")
    if not parcels:
        print(f"{LOG_PREFIX} No parcels in index.")
        return 0

    stored = 0
    for parcel in parcels:
        try:
            score, reasons, is_priority = score_development_candidate(parcel)

            # Always include priority parcels even if score is below threshold
            if score < min_score and not is_priority:
                continue

            now = now_ts()
            execute(
                """INSERT OR REPLACE INTO candidate_parcels
                   (id, parcel_id, development_candidate_score, btr_priority,
                    score_reasons, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                [new_id(), parcel["parcel_id"], score,
                 1 if is_priority else 0,
                 json.dumps(reasons), now, now]
            )
            stored += 1
        except Exception as e:
            print(f"{LOG_PREFIX} Error scoring parcel {parcel.get('parcel_id')}: {e}")

    print(f"{LOG_PREFIX} Stored {stored} candidate parcels.")
    return stored


# ============================================================================
# Step 3 — Parcel Deep Search
# ============================================================================

def deep_search_parcel(parcel_id):
    """
    For a candidate parcel, search across entity filings, engineering firms,
    planning agendas, zoning requests, contractor signals, utility planning,
    and nearby land purchases. Returns list of discovered signal dicts.
    """
    parcel = fetch_one(
        "SELECT * FROM parcel_index WHERE parcel_id = ?", [parcel_id]
    )
    if not parcel:
        return []

    city = parcel.get("city")
    state = parcel.get("state")
    lat = parcel.get("latitude") or 0
    lon = parcel.get("longitude") or 0
    owner = parcel.get("owner_entity") or ""
    since = (datetime.utcnow() - timedelta(days=365)).isoformat()
    signals = []

    for table, name_col, label in DEEP_SEARCH_SOURCES:
        try:
            # Location-based search
            rows = fetch_all(
                f"SELECT * FROM {table} "
                f"WHERE ((city = ? AND state = ?) "
                f"   OR (ABS(latitude - ?) < 0.01 AND ABS(longitude - ?) < 0.01)) "
                f"AND created_at >= ? "
                f"LIMIT 20",
                [city, state, lat, lon, since]
            )
            for row in rows:
                signals.append({
                    "parcel_id": parcel_id,
                    "signal_type": label,
                    "source_table": table,
                    "source_id": row.get("id"),
                    "detail": row.get(name_col, ""),
                    "signal_date": row.get("created_at"),
                })

            # Owner-entity match (if owner is known)
            if owner:
                entity_rows = fetch_all(
                    f"SELECT * FROM {table} "
                    f"WHERE {name_col} LIKE ? AND created_at >= ? "
                    f"LIMIT 10",
                    [f"%{owner}%", since]
                )
                for row in entity_rows:
                    signals.append({
                        "parcel_id": parcel_id,
                        "signal_type": f"{label} (Entity Match)",
                        "source_table": table,
                        "source_id": row.get("id"),
                        "detail": row.get(name_col, ""),
                        "signal_date": row.get("created_at"),
                    })
        except Exception:
            # Table may not exist — skip silently
            pass

    return signals


def deep_search_all_candidates():
    """Run deep search on every candidate parcel. Returns total signal count."""
    candidates = fetch_all("SELECT parcel_id FROM candidate_parcels")
    total = 0
    for c in candidates:
        sigs = deep_search_parcel(c["parcel_id"])
        total += len(sigs)
        if sigs:
            print(f"{LOG_PREFIX} Parcel {c['parcel_id']}: {len(sigs)} signals discovered")
    print(f"{LOG_PREFIX} Deep search complete — {total} total signals across {len(candidates)} candidates.")
    return total


# ============================================================================
# Step 4 — Parcel Cluster Detection
# ============================================================================

def ensure_parcel_clusters_table():
    """Create parcel_clusters table if it does not exist."""
    execute("""
        CREATE TABLE IF NOT EXISTS parcel_clusters (
            cluster_id          TEXT PRIMARY KEY,
            parcel_ids          TEXT,
            total_acreage       REAL,
            owner_entities      TEXT,
            cluster_center_lat  REAL,
            cluster_center_lon  REAL,
            created_at          TEXT,
            updated_at          TEXT
        )
    """)


def _haversine_miles(lat1, lon1, lat2, lon2):
    """Calculate distance in miles between two lat/lon points."""
    R = 3958.8  # Earth radius in miles
    lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    return 2 * R * math.asin(math.sqrt(a))


def detect_parcel_clusters():
    """
    Group candidate parcels within CLUSTER_RADIUS_MILES of each other.
    A cluster must have combined acreage >= CLUSTER_MIN_ACREAGE.
    Uses simple greedy clustering — parcels are visited once.
    """
    ensure_parcel_clusters_table()

    candidates = fetch_all(
        "SELECT p.parcel_id, p.latitude, p.longitude, p.acreage, "
        "p.owner_entity FROM parcel_index p "
        "INNER JOIN candidate_parcels c ON c.parcel_id = p.parcel_id "
        "WHERE p.latitude IS NOT NULL AND p.longitude IS NOT NULL"
    )
    if not candidates:
        print(f"{LOG_PREFIX} No candidates with coordinates for clustering.")
        return 0

    assigned = set()
    clusters = []

    for i, seed in enumerate(candidates):
        if seed["parcel_id"] in assigned:
            continue

        cluster_parcels = [seed]
        assigned.add(seed["parcel_id"])

        for j, other in enumerate(candidates):
            if other["parcel_id"] in assigned:
                continue
            dist = _haversine_miles(
                seed["latitude"], seed["longitude"],
                other["latitude"], other["longitude"]
            )
            if dist <= CLUSTER_RADIUS_MILES:
                cluster_parcels.append(other)
                assigned.add(other["parcel_id"])

        total_acreage = sum(p.get("acreage") or 0 for p in cluster_parcels)
        if total_acreage < CLUSTER_MIN_ACREAGE or len(cluster_parcels) < 2:
            continue

        parcel_ids = [p["parcel_id"] for p in cluster_parcels]
        owners = list({p.get("owner_entity") for p in cluster_parcels if p.get("owner_entity")})
        center_lat = sum(p["latitude"] for p in cluster_parcels) / len(cluster_parcels)
        center_lon = sum(p["longitude"] for p in cluster_parcels) / len(cluster_parcels)

        cid = new_id()
        now = now_ts()
        execute(
            """INSERT OR REPLACE INTO parcel_clusters
               (cluster_id, parcel_ids, total_acreage, owner_entities,
                cluster_center_lat, cluster_center_lon, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            [cid, json.dumps(parcel_ids), total_acreage,
             json.dumps(owners), center_lat, center_lon, now, now]
        )
        clusters.append(cid)

    print(f"{LOG_PREFIX} Detected {len(clusters)} parcel clusters.")
    return len(clusters)


# ============================================================================
# Step 5 — BTR Pattern Bias
# ============================================================================

def _check_btr_patterns(parcel, deep_signals):
    """
    Evaluate BTR-specific indicators for a parcel.
    Returns (btr_boost, reasons).

    Indicators:
    - Single developer owning multiple parcels
    - Subdivision-style land configuration
    - Acreage between 10 and 80 acres
    - Near suburban population growth corridors
    - Developer historically involved in BTR
    """
    btr_boost = 0
    reasons = []
    owner = parcel.get("owner_entity") or ""
    acreage = parcel.get("acreage") or 0

    # Acreage in BTR sweet spot (10-80 acres)
    if 10 <= acreage <= 80:
        btr_boost += 10
        reasons.append(f"BTR acreage sweet spot ({acreage:.1f} acres)")

    # Single developer owning multiple parcels
    if owner:
        multi = fetch_one(
            "SELECT COUNT(*) as cnt FROM parcel_index WHERE owner_entity = ?",
            [owner]
        )
        if multi and (multi.get("cnt") or 0) >= 2:
            btr_boost += 15
            reasons.append(f"Developer owns {multi['cnt']} parcels")

    # Developer historically involved in BTR
    if owner:
        btr_history = fetch_one(
            "SELECT id FROM developer_profiles "
            "WHERE developer_name LIKE ? AND btr_flag = 1 LIMIT 1",
            [f"%{owner}%"]
        )
        if not btr_history:
            btr_history = fetch_one(
                "SELECT id FROM predicted_projects "
                "WHERE developer LIKE ? AND project_type LIKE '%BTR%' LIMIT 1",
                [f"%{owner}%"]
            )
        if btr_history:
            btr_boost += 20
            reasons.append("Developer has BTR history")

    # Subdivision-style signals in deep search
    subdiv_keywords = {"subdivision", "plat", "lot", "phase", "section"}
    for sig in deep_signals:
        detail = (sig.get("detail") or "").lower()
        if any(kw in detail for kw in subdiv_keywords):
            btr_boost += 10
            reasons.append("Subdivision-style signals detected")
            break

    # Near suburban population growth corridors
    city = parcel.get("city")
    state = parcel.get("state")
    if city and state:
        growth = fetch_one(
            "SELECT population_growth FROM market_growth_data "
            "WHERE city = ? AND state = ? ORDER BY created_at DESC LIMIT 1",
            [city, state]
        )
        if growth and (growth.get("population_growth") or 0) >= 2:
            btr_boost += 10
            reasons.append("Suburban growth corridor")

    return min(btr_boost, 50), reasons


# ============================================================================
# Step 6 — Signal Attachment
# ============================================================================

SIGNAL_ATTACHMENT_SOURCES = [
    ("traffic_impact_studies",      "Traffic Impact Study"),
    ("civil_engineering_plans",     "Civil Engineering Plan"),
    ("utility_expansion_requests",  "Utility Expansion"),
    ("planning_agenda_items",       "Planning Commission Mention"),
    ("plat_filings",                "Plat Filing"),
]


def attach_signals_to_parcels():
    """
    Scan external signal tables and attach any signals that occur near
    candidate parcels. Updates development probability when signals appear.
    Returns count of attached signals.
    """
    candidates = fetch_all(
        "SELECT p.parcel_id, p.latitude, p.longitude, p.city, p.state "
        "FROM parcel_index p "
        "INNER JOIN candidate_parcels c ON c.parcel_id = p.parcel_id "
        "WHERE p.latitude IS NOT NULL AND p.longitude IS NOT NULL"
    )
    if not candidates:
        return 0

    attached = 0
    since = (datetime.utcnow() - timedelta(days=180)).isoformat()

    for table, label in SIGNAL_ATTACHMENT_SOURCES:
        for parcel in candidates:
            try:
                nearby = fetch_all(
                    f"SELECT id, created_at FROM {table} "
                    f"WHERE ((city = ? AND state = ?) "
                    f"   OR (ABS(latitude - ?) < 0.01 AND ABS(longitude - ?) < 0.01)) "
                    f"AND created_at >= ? LIMIT 10",
                    [parcel["city"], parcel["state"],
                     parcel["latitude"], parcel["longitude"], since]
                )
                if nearby:
                    # Boost the candidate score
                    execute(
                        "UPDATE candidate_parcels "
                        "SET development_candidate_score = MIN(development_candidate_score + 5, 100), "
                        "    updated_at = ? "
                        "WHERE parcel_id = ?",
                        [now_ts(), parcel["parcel_id"]]
                    )
                    attached += len(nearby)
            except Exception:
                # Table may not exist
                pass

    print(f"{LOG_PREFIX} Attached {attached} signals to candidate parcels.")
    return attached


# ============================================================================
# Step 7 — Opportunity Generation
# ============================================================================

def ensure_parcel_opportunities_table():
    """Create parcel_opportunities table if it does not exist."""
    execute("""
        CREATE TABLE IF NOT EXISTS parcel_opportunities (
            id                      TEXT PRIMARY KEY,
            parcel_ids              TEXT,
            cluster_id              TEXT,
            development_probability INTEGER,
            btr_probability         INTEGER,
            signals_detected        TEXT,
            first_signal_date       TEXT,
            latest_signal_date      TEXT,
            event_type              TEXT DEFAULT 'DEVELOPMENT_PARCEL_OPPORTUNITY',
            created_at              TEXT,
            updated_at              TEXT
        )
    """)


def generate_opportunities():
    """
    Evaluate candidate parcels and clusters. If development probability
    is high enough, emit a DEVELOPMENT_PARCEL_OPPORTUNITY event.
    Priority (BTR niche) parcels use a lower threshold.
    """
    ensure_parcel_opportunities_table()

    candidates = fetch_all(
        "SELECT c.parcel_id, c.development_candidate_score, c.btr_priority, "
        "c.score_reasons "
        "FROM candidate_parcels c "
        "ORDER BY c.btr_priority DESC, c.development_candidate_score DESC"
    )

    opportunities = 0
    for cand in candidates:
        parcel_id = cand["parcel_id"]
        base_score = cand.get("development_candidate_score") or 0
        is_priority = cand.get("btr_priority") == 1

        # Deep signals for BTR boost
        deep_sigs = deep_search_parcel(parcel_id)
        parcel = fetch_one("SELECT * FROM parcel_index WHERE parcel_id = ?", [parcel_id])
        btr_boost, btr_reasons = _check_btr_patterns(parcel, deep_sigs) if parcel else (0, [])

        dev_probability = min(base_score + (len(deep_sigs) * 2), 100)
        btr_probability = min(btr_boost + (10 if is_priority else 0), 100)

        # Use lower threshold for priority parcels
        threshold = BTR_OPPORTUNITY_THRESHOLD if is_priority else OPPORTUNITY_THRESHOLD

        if dev_probability < threshold and btr_probability < 30:
            continue

        # Find signal date range
        signal_dates = [s.get("signal_date") for s in deep_sigs if s.get("signal_date")]
        first_date = min(signal_dates) if signal_dates else None
        latest_date = max(signal_dates) if signal_dates else None

        # Check if parcel belongs to a cluster
        cluster_id = None
        clusters = fetch_all("SELECT cluster_id, parcel_ids FROM parcel_clusters")
        for cl in clusters:
            try:
                pids = json.loads(cl.get("parcel_ids") or "[]")
                if parcel_id in pids:
                    cluster_id = cl["cluster_id"]
                    break
            except Exception:
                pass

        signal_summary = list({s["signal_type"] for s in deep_sigs})
        now = now_ts()

        execute(
            """INSERT OR REPLACE INTO parcel_opportunities
               (id, parcel_ids, cluster_id, development_probability,
                btr_probability, signals_detected,
                first_signal_date, latest_signal_date,
                event_type, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [new_id(), json.dumps([parcel_id]), cluster_id,
             dev_probability, btr_probability,
             json.dumps(signal_summary),
             first_date, latest_date,
             "DEVELOPMENT_PARCEL_OPPORTUNITY", now, now]
        )
        opportunities += 1
        print(f"{LOG_PREFIX} Opportunity: parcel={parcel_id} "
              f"dev={dev_probability} btr={btr_probability} "
              f"signals={len(deep_sigs)}"
              + (" [PRIORITY]" if is_priority else ""))

    # Also generate cluster-level opportunities
    cluster_opps = _generate_cluster_opportunities()
    opportunities += cluster_opps

    print(f"{LOG_PREFIX} Generated {opportunities} opportunities.")
    return opportunities


def _generate_cluster_opportunities():
    """Generate opportunities for parcel clusters that meet thresholds."""
    clusters = fetch_all("SELECT * FROM parcel_clusters")
    count = 0

    for cluster in clusters:
        try:
            parcel_ids = json.loads(cluster.get("parcel_ids") or "[]")
        except Exception:
            continue

        if not parcel_ids:
            continue

        total_acreage = cluster.get("total_acreage") or 0
        owners = []
        try:
            owners = json.loads(cluster.get("owner_entities") or "[]")
        except Exception:
            pass

        # Aggregate signals across cluster parcels
        all_signals = []
        for pid in parcel_ids:
            all_signals.extend(deep_search_parcel(pid))

        if not all_signals:
            continue

        # Cluster-level scoring
        dev_prob = min(40 + len(all_signals) * 3 + int(total_acreage), 100)
        btr_prob = 0

        # BTR bias for clusters
        if 15 <= total_acreage <= 200:
            btr_prob += 15
        if len(owners) == 1:
            btr_prob += 20  # single entity controlling cluster
        if any("subdivision" in (s.get("detail") or "").lower() for s in all_signals):
            btr_prob += 15
        btr_prob = min(btr_prob, 100)

        if dev_prob < OPPORTUNITY_THRESHOLD and btr_prob < 30:
            continue

        signal_dates = [s.get("signal_date") for s in all_signals if s.get("signal_date")]
        signal_types = list({s["signal_type"] for s in all_signals})
        now = now_ts()

        execute(
            """INSERT OR REPLACE INTO parcel_opportunities
               (id, parcel_ids, cluster_id, development_probability,
                btr_probability, signals_detected,
                first_signal_date, latest_signal_date,
                event_type, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [new_id(), json.dumps(parcel_ids), cluster["cluster_id"],
             dev_prob, btr_prob,
             json.dumps(signal_types),
             min(signal_dates) if signal_dates else None,
             max(signal_dates) if signal_dates else None,
             "DEVELOPMENT_PARCEL_OPPORTUNITY", now, now]
        )
        count += 1
        print(f"{LOG_PREFIX} Cluster opportunity: {cluster['cluster_id']} "
              f"parcels={len(parcel_ids)} acreage={total_acreage:.1f} "
              f"dev={dev_prob} btr={btr_prob}")

    return count


# ============================================================================
# Step 8 — Integration Helpers
# ============================================================================

def get_radar_map_data():
    """
    Return parcel opportunities formatted for the Development Radar Map.
    Includes coordinates and probability data.
    """
    opps = fetch_all(
        "SELECT o.*, p.latitude, p.longitude, p.city, p.state, p.acreage, "
        "p.owner_entity, p.zoning_type "
        "FROM parcel_opportunities o "
        "LEFT JOIN parcel_index p ON JSON_EXTRACT(o.parcel_ids, '$[0]') = p.parcel_id "
        "ORDER BY o.btr_probability DESC, o.development_probability DESC"
    )
    if not opps:
        # Fallback for databases without JSON_EXTRACT
        opps = fetch_all(
            "SELECT * FROM parcel_opportunities "
            "ORDER BY btr_probability DESC, development_probability DESC"
        )
    return opps


def get_opportunity_feed(limit=50):
    """
    Return recent parcel opportunities for the Opportunity Feed.
    Prioritizes BTR-niche matches.
    """
    return fetch_all(
        "SELECT * FROM parcel_opportunities "
        "ORDER BY btr_probability DESC, development_probability DESC, "
        "latest_signal_date DESC LIMIT ?",
        [limit]
    )


def get_developer_intelligence(developer_name):
    """
    Return parcel opportunities linked to a specific developer for
    Developer Intelligence Profiles.
    """
    parcels = fetch_all(
        "SELECT parcel_id FROM parcel_index WHERE owner_entity LIKE ?",
        [f"%{developer_name}%"]
    )
    if not parcels:
        return []

    parcel_ids = [p["parcel_id"] for p in parcels]
    results = []
    all_opps = fetch_all("SELECT * FROM parcel_opportunities")
    for opp in all_opps:
        try:
            opp_pids = json.loads(opp.get("parcel_ids") or "[]")
            if any(pid in parcel_ids for pid in opp_pids):
                results.append(opp)
        except Exception:
            pass

    return results


def format_opportunity_summary(opportunity):
    """
    Format an opportunity into a human-readable summary.

    Example output:
        "Potential BTR Community Development Detected"
    """
    btr_prob = opportunity.get("btr_probability") or 0
    dev_prob = opportunity.get("development_probability") or 0
    signals = opportunity.get("signals_detected") or "[]"

    try:
        signal_list = json.loads(signals) if isinstance(signals, str) else signals
    except Exception:
        signal_list = []

    if btr_prob >= 40:
        headline = "Potential BTR Community Development Detected"
    elif dev_prob >= 70:
        headline = "High-Probability Development Parcel Detected"
    else:
        headline = "Development Candidate Parcel Identified"

    return {
        "headline": headline,
        "development_probability": dev_prob,
        "btr_probability": btr_prob,
        "signal_count": len(signal_list),
        "signals": signal_list,
        "parcel_ids": opportunity.get("parcel_ids"),
        "cluster_id": opportunity.get("cluster_id"),
    }


# ============================================================================
# Full Pipeline
# ============================================================================

def ensure_all_tables():
    """Create all tables used by the parcel-first search engine."""
    ensure_parcel_index_table()
    ensure_candidate_parcels_table()
    ensure_parcel_clusters_table()
    ensure_parcel_opportunities_table()


def run():
    """
    Execute the full Parcel First Search pipeline.

    1. Filter development candidates from parcel_index
    2. Run deep search on candidates
    3. Detect parcel clusters
    4. Attach external signals
    5. Generate opportunities (with BTR bias + priority filtering)
    """
    print(f"{LOG_PREFIX} Starting Parcel First Search Engine...")
    ensure_all_tables()

    print(f"{LOG_PREFIX} Step 2: Filtering development candidates...")
    candidates = filter_development_candidates()

    print(f"{LOG_PREFIX} Step 3: Deep searching candidate parcels...")
    signals = deep_search_all_candidates()

    print(f"{LOG_PREFIX} Step 4: Detecting parcel clusters...")
    clusters = detect_parcel_clusters()

    print(f"{LOG_PREFIX} Step 6: Attaching external signals...")
    attached = attach_signals_to_parcels()

    print(f"{LOG_PREFIX} Step 7: Generating opportunities...")
    opportunities = generate_opportunities()

    print(f"{LOG_PREFIX} Complete.")
    print(f"{LOG_PREFIX}   Candidates: {candidates}")
    print(f"{LOG_PREFIX}   Deep signals: {signals}")
    print(f"{LOG_PREFIX}   Clusters: {clusters}")
    print(f"{LOG_PREFIX}   Attached signals: {attached}")
    print(f"{LOG_PREFIX}   Opportunities: {opportunities}")

    return {
        "candidates": candidates,
        "deep_signals": signals,
        "clusters": clusters,
        "attached_signals": attached,
        "opportunities": opportunities,
    }


if __name__ == "__main__":
    run()
