"""
Predicted Project Optimizer.
Master job that runs every 12 hours to refresh the predicted_project_index
with enriched scoring: multi-signal confidence, developer reputation,
geographic clusters, timeline estimation, signal freshness, and contactability.
"""
import json
import uuid
import traceback
from datetime import datetime, timedelta

from db import get_db


def _count_signals(cur, city, state):
    """Count total development events for a city/state."""
    cur.execute('''
        SELECT COUNT(*) FROM development_events
        WHERE city = ? AND state = ?
    ''', (city, state))
    return cur.fetchone()[0]


def _get_event_types(cur, city, state):
    """Get distinct event types for a city/state."""
    cur.execute('''
        SELECT DISTINCT event_type FROM development_events
        WHERE city = ? AND state = ?
    ''', (city, state))
    return set(r[0] for r in cur.fetchall() if r[0])


def _compute_multi_signal_score(event_types, signal_count):
    """
    Multi-signal confidence scoring (Step 1).
    base_score = 50
    +20 if ZONING_CASE detected
    +15 if SUBDIVISION_PLAT detected
    +10 if LAND_PURCHASE detected
    +15 if CONTRACTOR_BID detected
    +10 if PERMIT_APPLICATION detected
    """
    score = 50
    if 'ZONING_CASE' in event_types:
        score += 20
    if 'SUBDIVISION_PLAT' in event_types:
        score += 15
    if 'LAND_PURCHASE' in event_types:
        score += 10
    if 'CONTRACTOR_BID' in event_types:
        score += 15
    if 'PERMIT_APPLICATION' in event_types:
        score += 10
    return score


def _compute_developer_reputation(cur, developer):
    """
    Developer reputation boost (Step 2).
    +15 if known_btr_builder
    +10 if historical_projects > 5
    +10 if developer appears in multiple signals (handled separately)
    """
    if not developer:
        return 0
    cur.execute('''
        SELECT known_btr_builder, historical_projects
        FROM developer_profiles
        WHERE developer_name = ?
    ''', (developer,))
    row = cur.fetchone()
    if not row:
        return 0
    boost = 0
    # known_btr_builder — handle both bool and int representations
    if row[0] and row[0] not in (0, False, '0', 'false'):
        boost += 15
    if row[1] and row[1] > 5:
        boost += 10
    return boost


def _compute_developer_multi_signal(cur, developer, city, state):
    """
    +10 if developer appears in multiple development events.
    """
    if not developer:
        return 0
    cur.execute('''
        SELECT COUNT(*) FROM development_events
        WHERE developer = ? AND city = ? AND state = ?
    ''', (developer, city, state))
    count = cur.fetchone()[0]
    return 10 if count >= 2 else 0


def _compute_project_size_boost(cur, developer, city, state):
    """
    +10 if project size > 150 units (from metadata or developer profile).
    """
    # Check metadata for unit mentions
    cur.execute('''
        SELECT metadata FROM development_events
        WHERE city = ? AND state = ?
        AND metadata IS NOT NULL
    ''', (city, state))
    for row in cur.fetchall():
        try:
            meta = json.loads(row[0]) if isinstance(row[0], str) else row[0]
            units = meta.get('unit_count') or meta.get('units')
            if units and int(units) > 150:
                return 10
        except Exception:
            pass

    # Check developer profile avg_project_size
    if developer:
        cur.execute('''
            SELECT avg_project_size FROM developer_profiles
            WHERE developer_name = ?
        ''', (developer,))
        row = cur.fetchone()
        if row and row[0] and row[0] > 150:
            return 10

    return 0


def _compute_freshness_boost(cur, city, state):
    """
    Signal freshness boost (Step 6).
    Most recent signal < 7 days → +20
    Most recent signal < 14 days → +15
    Most recent signal < 30 days → +10
    Otherwise → 0
    """
    cur.execute('''
        SELECT MAX(created_at) FROM development_events
        WHERE city = ? AND state = ?
    ''', (city, state))
    row = cur.fetchone()
    if not row or not row[0]:
        return 0

    latest = row[0]
    try:
        if isinstance(latest, str):
            latest = datetime.fromisoformat(latest.replace('Z', '+00:00').replace('+00:00', ''))
        age_days = (datetime.utcnow() - latest).days
    except Exception:
        return 0

    if age_days < 7:
        return 20
    elif age_days < 14:
        return 15
    elif age_days < 30:
        return 10
    return 0


def _compute_contactability(cur, developer, city, state):
    """
    Contactability score (Step 7).
    +15 if developer contact name identified
    +10 if email pattern found
    +5 if phone number detected
    """
    score = 0

    # Check development events metadata for contact info
    cur.execute('''
        SELECT metadata FROM development_events
        WHERE city = ? AND state = ?
        AND metadata IS NOT NULL
    ''', (city, state))

    import re
    for row in cur.fetchall():
        try:
            meta_str = row[0] if isinstance(row[0], str) else json.dumps(row[0], default=str)

            # Check for contact name patterns
            if re.search(r'(?:contact|manager|director|vp|president|ceo|cfo)\s*[:=]?\s*[A-Z][a-z]+\s+[A-Z][a-z]+', meta_str, re.IGNORECASE):
                score = max(score, 15)

            # Check for email patterns
            if re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', meta_str):
                score = max(score, score if score >= 15 else 0)
                score += 10 if score < 25 else 0

            # Check for phone patterns
            if re.search(r'\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}', meta_str):
                score += 5 if score < 30 else 0
        except Exception:
            pass

    # Also check li_contacts for the developer's company
    if developer:
        try:
            cur.execute('''
                SELECT COUNT(*) FROM li_contacts c
                JOIN li_companies co ON co.id = c.company_id
                WHERE co.name = ?
            ''', (developer,))
            contact_count = cur.fetchone()[0]
            if contact_count > 0 and score < 15:
                score = 15
        except Exception:
            pass  # li_contacts may not exist or be empty

    return min(30, score)


def run_optimizer():
    """
    Master optimization pipeline. Refreshes predicted_project_index.
    Steps:
    1. Get all predicted_projects
    2. For each: compute multi-signal score, developer reputation,
       cluster detection, timeline, freshness, contactability
    3. Write results to predicted_project_index
    4. Update predicted_projects with new columns
    """
    print(f"\n{'='*60}")
    print(f"[Optimizer] START — {datetime.utcnow().isoformat()}")
    print(f"{'='*60}\n")

    conn = get_db()
    cur = conn.cursor()

    # Step 0: Load cluster data
    try:
        from workers.analysis.geographic_cluster_detector import get_cluster_cities
        cluster_cities = get_cluster_cities()
    except Exception as e:
        print(f"[Optimizer] Cluster detection error: {e}")
        cluster_cities = set()

    # Step 1: Get all predicted_projects
    cur.execute('''
        SELECT id, city, state, developer, prediction_date, confidence,
               pattern_detected, confirmed
        FROM predicted_projects
        ORDER BY confidence DESC
    ''')
    predictions = cur.fetchall()
    col_names = [d[0] for d in cur.description]

    if not predictions:
        conn.close()
        print("[Optimizer] No predictions to optimize.")
        return {'optimized': 0}

    # Clear the index table for refresh
    cur.execute("DELETE FROM predicted_project_index")

    optimized = 0

    for row in predictions:
        pred = dict(zip(col_names, row))
        city = pred.get('city')
        state = pred.get('state')
        developer = pred.get('developer')

        if not city or not state:
            continue

        # Gather data
        signal_count = _count_signals(cur, city, state)
        event_types = _get_event_types(cur, city, state)

        # Compute all score components
        multi_signal = _compute_multi_signal_score(event_types, signal_count)
        dev_reputation = _compute_developer_reputation(cur, developer)
        dev_multi = _compute_developer_multi_signal(cur, developer, city, state)
        size_boost = _compute_project_size_boost(cur, developer, city, state)
        freshness = _compute_freshness_boost(cur, city, state)
        contactability = _compute_contactability(cur, developer, city, state)

        # Cluster detection
        cluster = (city.lower(), state.upper()) in cluster_cities
        cluster_boost = 20 if cluster else 0

        # Timeline estimation
        try:
            from workers.predictions.timeline_estimator import estimate_timeline_from_events
            timeline = estimate_timeline_from_events(event_types)
        except Exception:
            timeline = None

        # Final confidence = multi_signal + boosts, capped at 100
        final_confidence = min(100, (
            multi_signal +
            dev_reputation +
            dev_multi +
            size_boost +
            cluster_boost +
            freshness +
            contactability
        ))

        # Insert into index
        try:
            cur.execute('''
                INSERT INTO predicted_project_index
                (id, city, state, developer, confidence, signal_count,
                 cluster_detected, expected_construction_window, prediction_date,
                 confirmed, pattern_detected, freshness_boost, contactability_score,
                 developer_reputation_boost, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (
                pred['id'], city, state, developer,
                final_confidence, signal_count,
                1 if cluster else 0,
                timeline,
                pred.get('prediction_date'),
                1 if pred.get('confirmed') else 0,
                pred.get('pattern_detected'),
                freshness,
                contactability,
                dev_reputation + dev_multi,
            ))

            # Also update predicted_projects with new columns
            cur.execute('''
                UPDATE predicted_projects
                SET confidence = ?, signal_count = ?,
                    cluster_detected = ?,
                    expected_construction_window = ?
                WHERE id = ?
            ''', (
                final_confidence, signal_count,
                1 if cluster else 0,
                timeline,
                pred['id'],
            ))

            optimized += 1
        except Exception as e:
            print(f"[Optimizer] Error processing {city}, {state}: {e}")

    conn.commit()
    conn.close()

    print(f"\n{'='*60}")
    print(f"[Optimizer] COMPLETE — {optimized}/{len(predictions)} predictions optimized")
    print(f"[Optimizer] Clusters found: {len(cluster_cities)}")
    print(f"{'='*60}\n")

    return {'optimized': optimized, 'clusters': len(cluster_cities)}
